(function () {
  'use strict';

  let scanTimeout = null;
  // Track all findings across DOM + network for highlighting and badge
  let allFindings = [];
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
    return document.documentElement?.outerHTML || '';
  }

  function isContextValid() {
    try {
      return !!chrome.runtime?.id;
    } catch {
      return false;
    }
  }

  async function sendForScan(text, url, source) {
    if (!text || text.length < 10) return;
    if (!isContextValid()) return;

    const hash = await hashText(text);
    if (scannedHashes.has(hash)) return;
    scannedHashes.add(hash);

    try {
      chrome.runtime.sendMessage(
        { type: 'SCAN_TEXT', text, url, source },
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
    if (event.data?.type !== '__SECRETS_SPOTTER_INTERCEPT__') return;

    const { url, text, source } = event.data;
    sendForScan(text, url, `network:${source}`);
  });

  function highlightFindings(findings) {
    document.querySelectorAll('.secrets-spotter-highlight').forEach((el) => {
      const text = document.createTextNode(el.textContent);
      el.replaceWith(text);
    });

    const treeWalker = document.createTreeWalker(
      document.body,
      NodeFilter.SHOW_TEXT,
      null
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
        } catch {
          // Skip if range crosses element boundaries
        }
        break;
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
          pendingNodes.push(node);
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
})();
