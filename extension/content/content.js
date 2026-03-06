(function () {
  'use strict';

  let scanTimeout = null;
  // Track all findings across DOM + network for highlighting and badge
  let allFindings = [];

  function getPageSource() {
    return document.documentElement?.outerHTML || '';
  }

  function sendForScan(text, url, source) {
    if (!text || text.length < 10) return;

    chrome.runtime.sendMessage(
      { type: 'SCAN_TEXT', text, url, source },
      (response) => {
        if (chrome.runtime.lastError) {
          console.warn('Secrets Spotter:', chrome.runtime.lastError.message);
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
  }

  function scanPage() {
    sendForScan(getPageSource(), window.location.href, 'dom');
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

  const observer = new MutationObserver(() => {
    clearTimeout(scanTimeout);
    scanTimeout = setTimeout(scanPage, 2000);
  });

  const target = document.body || document.documentElement;
  if (target) {
    observer.observe(target, { childList: true, subtree: true });
  }
})();
