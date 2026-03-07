(function () {
  'use strict';

  function logError(msg, stack) {
    if (!isContextValid()) return;
    try {
      chrome.runtime.sendMessage({
        type: 'LOG_ERROR',
        src: 'content',
        msg,
        stack: stack || null,
        url: window.location.href,
      });
    } catch { /* context destroyed */ }
  }

  window.addEventListener('error', (event) => {
    logError(event.message, event.error?.stack);
  });

  window.addEventListener('unhandledrejection', (event) => {
    const msg = event.reason?.message || String(event.reason);
    logError(msg, event.reason?.stack);
  });

  let scanTimeout = null;
  // Hash-based cache to skip already-scanned text
  const scannedHashes = new Set();
  let observer = null;

  async function hashText(text) {
    const encoded = new TextEncoder().encode(text);
    const buffer = await crypto.subtle.digest('SHA-256', encoded);
    const arr = new Uint8Array(buffer);
    let hex = '';
    for (const b of arr) hex += b.toString(16).padStart(2, '0');
    return hex;
  }

  function getPageSource() {
    const clone = document.documentElement.cloneNode(true);
    clone.querySelectorAll('.secrets-spotter-highlight').forEach((el) => {
      el.replaceWith(document.createTextNode(el.textContent));
    });
    return clone.outerHTML || '';
  }

  function isContextValid() {
    try {
      return !!chrome.runtime?.id;
    } catch {
      return false;
    }
  }

  async function sendForScan(text, url, source, contentType) {
    if (!text || text.length < 10) return;
    if (!isContextValid()) return;

    const hash = await hashText(text);
    if (scannedHashes.has(hash)) return;
    scannedHashes.add(hash);

    try {
      chrome.runtime.sendMessage(
        { type: 'SCAN_TEXT', text, url, source, contentType: contentType || '' },
        (response) => {
          if (chrome.runtime.lastError) {
            // Extension was reloaded/updated — stop scanning
            if (chrome.runtime.lastError.message?.includes('context invalidated')) {
              observer?.disconnect();
            }
            return;
          }
          if (response?.findings?.length > 0) {
            // Only highlight DOM-source findings (network ones aren't in the visible page)
            if (source === 'dom') {
              highlightFindings(response.findings);
            }
          }
        }
      );
    } catch {
      // Extension context destroyed — disconnect observer
      observer?.disconnect();
    }
  }

  function extractStructuredSecrets() {
    const pairs = [];

    // Extract <meta> tag name/content pairs
    const metas = document.querySelectorAll('meta[content]');
    for (const meta of metas) {
      const name = meta.getAttribute('name') || meta.getAttribute('property') || meta.getAttribute('http-equiv');
      const value = meta.getAttribute('content');
      if (name && value && value.length >= 8) {
        pairs.push({ name, value });
      }
    }

    // Extract data-* attributes from all elements
    const allElements = document.querySelectorAll('*');
    for (const el of allElements) {
      for (const attr of el.attributes) {
        if (attr.name.startsWith('data-') && attr.value.length >= 8) {
          pairs.push({ name: attr.name, value: attr.value });
        }
      }
    }

    return pairs.length > 0 ? JSON.stringify(pairs) : '';
  }

  function scanPage() {
    sendForScan(getPageSource(), window.location.href, 'dom');

    const structured = extractStructuredSecrets();
    if (structured) {
      sendForScan(structured, window.location.href, 'dom:structured');
    }
  }

  // Listen for intercepted network responses from the MAIN world script
  window.addEventListener('message', (event) => {
    if (event.source !== window) return;
    if (event.origin !== window.location.origin) return;

    if (event.data?.type === '__SECRETS_SPOTTER_NAVIGATION__') {
      // SPA navigation — clear DOM findings but keep network findings, then re-scan
      scannedHashes.clear();
      chrome.runtime.sendMessage({ type: 'CLEAR_DOM_FINDINGS' });
      scanPage();
      return;
    }

    if (event.data?.type !== '__SECRETS_SPOTTER_INTERCEPT__') return;

    const { url, text, source, contentType } = event.data;
    if (typeof text !== 'string') return;
    sendForScan(text, url, `network:${source}`, contentType);
  });

  function highlightFindings(findings) {
    const treeWalker = document.createTreeWalker(
      document.body,
      NodeFilter.SHOW_TEXT,
      {
        acceptNode(node) {
          if (node.parentElement?.closest('.secrets-spotter-highlight')) {
            return NodeFilter.FILTER_REJECT;
          }
          return NodeFilter.FILTER_ACCEPT;
        }
      }
    );

    const textNodes = [];
    while (treeWalker.nextNode()) {
      textNodes.push(treeWalker.currentNode);
    }

    for (const finding of findings) {
      for (const node of textNodes) {
        const idx = node.textContent.indexOf(finding.full_match);
        if (idx === -1) continue;

        const range = document.createRange();
        range.setStart(node, idx);
        range.setEnd(node, idx + finding.full_match.length);

        const highlight = document.createElement('span');
        highlight.className = 'secrets-spotter-highlight';
        highlight.dataset.secretKind = finding.label;
        highlight.dataset.severity = finding.severity;
        highlight.title = `${finding.label} (${finding.severity})`;

        try {
          range.surroundContents(highlight);
          break;
        } catch {
          // Skip if range crosses element boundaries
        }
      }
    }
  }

  if (document.readyState === 'complete') {
    scanPage();
  } else {
    window.addEventListener('load', () => scanPage());
  }

  let pendingNodes = [];

  observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node.nodeType === Node.ELEMENT_NODE || node.nodeType === Node.TEXT_NODE) {
          if (pendingNodes.length < 1000) {
            pendingNodes.push(node);
          }
        }
      }
    }
    if (pendingNodes.length === 0) return;

    clearTimeout(scanTimeout);
    scanTimeout = setTimeout(() => {
      const texts = [];
      for (const node of pendingNodes) {
        const text = node.textContent;
        if (text && text.length >= 10) {
          texts.push(text);
        }
      }
      pendingNodes = [];

      if (texts.length > 0) {
        const combined = texts.join('\n');
        sendForScan(combined, window.location.href, 'dom');
      }
    }, 2000);
  });

  const target = document.body || document.documentElement;
  if (target) {
    observer.observe(target, { childList: true, subtree: true });
  }

  // Detect extension context invalidation (e.g. extension update/reload)
  // Detect extension context invalidation (e.g. extension update/reload)
  const contextCheckInterval = setInterval(() => {
    if (typeof chrome === 'undefined' || !chrome.runtime?.id) {
      clearInterval(contextCheckInterval);
      if (observer) observer.disconnect();
      clearTimeout(scanTimeout);
      pendingNodes = [];
      // Signal MAIN world interceptor to clean up too
      window.dispatchEvent(new Event('__SECRETS_SPOTTER_CLEANUP__'));
    }
  }, 5000);

  window.addEventListener('pagehide', () => {
    clearInterval(contextCheckInterval);
    if (observer) {
      observer.disconnect();
    }
    clearTimeout(scanTimeout);
    pendingNodes = [];
  });
})();
