import init, { scan_text, pattern_count } from '../wasm/secrets_spotter_core.js';

const tabFindings = new Map();
let wasmReady = false;

async function initWasm() {
  if (wasmReady) return;
  const wasmUrl = chrome.runtime.getURL('wasm/secrets_spotter_core_bg.wasm');
  await init(wasmUrl);
  wasmReady = true;
  console.log(`Secrets Spotter WASM loaded. ${pattern_count()} patterns active.`);
}

function updateBadge(tabId, count) {
  const text = count > 0 ? String(count) : '';
  const color = count > 0 ? '#e74c3c' : '#4CAF50';
  chrome.action.setBadgeText({ text, tabId });
  chrome.action.setBadgeBackgroundColor({ color, tabId });
}

function getTabData(tabId) {
  if (!tabFindings.has(tabId)) {
    tabFindings.set(tabId, { findings: [], scannedUrls: new Set(), url: '' });
  }
  return tabFindings.get(tabId);
}

function deduplicateFindings(findings) {
  const seen = new Set();
  return findings.filter((f) => {
    const key = `${f.label}:${f.full_match}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'SCAN_TEXT') {
    const tabId = sender.tab?.id;
    initWasm().then(() => {
      const newFindings = scan_text(message.text);

      if (tabId != null) {
        const tabData = getTabData(tabId);
        tabData.url = tabData.url || message.url;

        // Tag each finding with its source
        for (const f of newFindings) {
          f.source = message.source || 'unknown';
          f.sourceUrl = message.url || '';
        }

        tabData.findings.push(...newFindings);
        tabData.findings = deduplicateFindings(tabData.findings);
        tabData.scannedUrls.add(message.url);
        updateBadge(tabId, tabData.findings.length);
      }

      sendResponse({ findings: newFindings });
    });
    return true;
  }

  if (message.type === 'GET_FINDINGS') {
    const tabId = message.tabId;
    const tabData = tabFindings.get(tabId);
    if (tabData) {
      sendResponse({
        findings: tabData.findings,
        url: tabData.url,
        scannedCount: tabData.scannedUrls.size,
      });
    } else {
      sendResponse({ findings: [], url: '', scannedCount: 0 });
    }
    return false;
  }
});

// Reset findings on navigation
chrome.webNavigation?.onCommitted?.addListener((details) => {
  if (details.frameId === 0) {
    tabFindings.delete(details.tabId);
    updateBadge(details.tabId, 0);
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabFindings.delete(tabId);
});
