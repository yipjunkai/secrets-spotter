import init, {
  scan_text,
  pattern_count,
  should_scan,
  parse_cookies,
  format_attributes,
  merge_findings,
} from '../wasm/secrets_spotter_core.js';

let wasmReady = false;
let wasmInitPromise = null;

const MAX_LOG_ENTRIES = 100;

async function appendToLog(entry) {
  try {
    const { errorLog = [] } = await chrome.storage.local.get('errorLog');
    const cutoff = Date.now() - (7 * 24 * 60 * 60 * 1000);
    const filtered = errorLog.filter(e => e.ts > cutoff);
    filtered.push(entry);
    if (filtered.length > MAX_LOG_ENTRIES) {
      filtered.splice(0, filtered.length - MAX_LOG_ENTRIES);
    }
    await chrome.storage.local.set({ errorLog: filtered });
  } catch (e) {
    console.warn('Secrets Spotter: failed to write error log:', e.message);
  }
}

function logEntry(src, msg, stack, url) {
  return { ts: Date.now(), src, msg, stack: stack || null, url: url || null };
}

self.addEventListener('error', (event) => {
  appendToLog(logEntry('service-worker', event.message, event.error?.stack));
});

self.addEventListener('unhandledrejection', (event) => {
  const msg = event.reason?.message || String(event.reason);
  appendToLog(logEntry('service-worker', msg, event.reason?.stack));
});

chrome.storage.session.setAccessLevel?.({ accessLevel: 'TRUSTED_CONTEXTS' });

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({ errorLog: [] });
});

async function initWasm() {
  if (wasmReady) return;
  if (wasmInitPromise) return wasmInitPromise;
  wasmInitPromise = (async () => {
    try {
      const wasmUrl = chrome.runtime.getURL('wasm/secrets_spotter_core_bg.wasm');
      await init(wasmUrl);
      wasmReady = true;
      console.log(`Secrets Spotter WASM loaded. ${pattern_count()} patterns active.`);
    } catch (err) {
      wasmInitPromise = null;
      throw err;
    }
  })();
  return wasmInitPromise;
}

const badgeSettleTimers = new Map();

function updateBadge(tabId, count) {
  if (count > 0) {
    // Immediately show the count
    clearTimeout(badgeSettleTimers.get(tabId));
    badgeSettleTimers.delete(tabId);
    chrome.action.setBadgeText({ text: String(count), tabId });
    chrome.action.setBadgeBackgroundColor({ color: '#e74c3c', tabId });
  } else {
    // Delay clearing "..." so it doesn't flash away between scan chunks.
    // If no findings arrive within 3s of the last scan, clear the badge.
    if (badgeSettleTimers.has(tabId)) return;
    const timer = setTimeout(() => {
      badgeSettleTimers.delete(tabId);
      chrome.action.setBadgeText({ text: '', tabId });
    }, 3000);
    badgeSettleTimers.set(tabId, timer);
  }
}

function tabKey(tabId) {
  return `tab:${tabId}`;
}

async function getTabData(tabId) {
  const key = tabKey(tabId);
  const result = await chrome.storage.session.get(key);
  return result[key] || { findings: [], scannedUrls: [], url: '', scanned: 0, skipped: 0, sources: {} };
}

async function setTabData(tabId, data) {
  await chrome.storage.session.set({ [tabKey(tabId)]: data });
}

async function removeTabData(tabId) {
  await chrome.storage.session.remove(tabKey(tabId));
}

const tabLocks = new Map();

async function withTabLock(tabId, fn) {
  const prev = tabLocks.get(tabId) || Promise.resolve();
  const next = prev.catch(() => {}).then(fn);
  tabLocks.set(tabId, next);
  return next;
}

function normalizeSource(source) {
  if (!source) return 'unknown';
  if (source === 'dom' || source === 'dom:structured') return 'dom';
  if (source === 'cookie') return 'cookie';
  // network:fetch, network:xhr, network:websocket, network:sse, etc.
  const match = source.match(/^network:(?:request:|header:)?(.+)$/);
  return match ? match[1] : source;
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'CLEAR_TAB') {
    const tabId = sender.tab?.id;
    if (tabId != null) {
      removeTabData(tabId).then(() => {
        updateBadge(tabId, 0);
        sendResponse({});
      });
    } else {
      sendResponse({});
    }
    return true;
  }
  if (message.type === 'CLEAR_DOM_FINDINGS') {
    const tabId = sender.tab?.id;
    if (tabId != null) {
      withTabLock(tabId, async () => {
        const tabData = await getTabData(tabId);
        tabData.findings = tabData.findings.filter(f => f.source && f.source !== 'dom' && f.source !== 'dom:structured');
        await setTabData(tabId, tabData);
        updateBadge(tabId, tabData.findings.length);
      }).then(() => sendResponse({}));
    } else {
      sendResponse({});
    }
    return true;
  }
  if (message.type === 'SCAN_TEXT') {
    const tabId = sender.tab?.id;
    initWasm().then(async () => {
      const source = normalizeSource(message.source);

      // Filter URLs that shouldn't be scanned
      const contentType = message.contentType || '';
      if (message.url && !should_scan(message.url, contentType)) {
        if (tabId != null) {
          await withTabLock(tabId, async () => {
            const tabData = await getTabData(tabId);
            tabData.skipped = (tabData.skipped || 0) + 1;
            await setTabData(tabId, tabData);
          });
        }
        sendResponse({ findings: [] });
        return;
      }

      // Preprocess based on source type
      let textToScan = message.text;
      if (message.source === 'cookie' || message.source === 'network:cookie') {
        textToScan = parse_cookies(message.text);
      } else if (message.source === 'dom:structured') {
        textToScan = format_attributes(message.text);
      }

      if (!textToScan || textToScan.length < 10) {
        sendResponse({ findings: [] });
        return;
      }

      const newFindings = scan_text(textToScan);

      if (tabId != null) {
        // Tag each finding with its source
        for (const f of newFindings) {
          f.source = message.source || 'unknown';
          f.sourceUrl = message.url || '';
        }

        await withTabLock(tabId, async () => {
          const tabData = await getTabData(tabId);
          tabData.url = tabData.url || message.url;

          // Deduplicate via Rust
          tabData.findings = merge_findings(tabData.findings, newFindings);

          if (message.url && !tabData.scannedUrls.includes(message.url)) {
            tabData.scannedUrls.push(message.url);
          }

          tabData.scanned = (tabData.scanned || 0) + 1;
          tabData.lastScanTs = Date.now();
          tabData.sources = tabData.sources || {};
          tabData.sources[source] = (tabData.sources[source] || 0) + 1;

          await setTabData(tabId, tabData);
          updateBadge(tabId, tabData.findings.length);
        });
      }

      sendResponse({ findings: newFindings });
    }).catch((err) => {
      console.warn('Secrets Spotter: scan failed:', err.message);
      appendToLog(logEntry('service-worker', `scan failed: ${err.message}`, err.stack));
      sendResponse({ findings: [] });
    });
    return true;
  }

  if (message.type === 'LOG_ERROR') {
    appendToLog(logEntry(
      message.src || 'unknown',
      message.msg || '',
      message.stack,
      message.url
    ));
    sendResponse({});
    return;
  }

  if (message.type === 'GET_ERROR_LOG') {
    chrome.storage.local.get('errorLog').then(({ errorLog = [] }) => {
      sendResponse({ errorLog });
    });
    return true;
  }

  if (message.type === 'CLEAR_ERROR_LOG') {
    chrome.storage.local.set({ errorLog: [] }).then(() => {
      sendResponse({});
    });
    return true;
  }

  if (message.type === 'GET_FINDINGS') {
    const tabId = message.tabId;
    getTabData(tabId).then((tabData) => {
      sendResponse({
        findings: tabData.findings,
        url: tabData.url,
        scannedCount: tabData.scanned || 0,
        skippedCount: tabData.skipped || 0,
        sources: tabData.sources || {},
        lastScanTs: tabData.lastScanTs || 0,
      });
    }).catch((err) => {
      console.warn('Secrets Spotter: get findings failed:', err.message);
      appendToLog(logEntry('service-worker', `get findings failed: ${err.message}`, err.stack));
      sendResponse({ findings: [], url: '', scannedCount: 0 });
    });
    return true;
  }
});

// Reset findings on navigation — show loading badge until first scan completes
chrome.webNavigation?.onCommitted?.addListener((details) => {
  if (details.frameId === 0) {
    removeTabData(details.tabId);
    clearTimeout(badgeSettleTimers.get(details.tabId));
    badgeSettleTimers.delete(details.tabId);
    chrome.action.setBadgeText({ text: '...', tabId: details.tabId });
    chrome.action.setBadgeBackgroundColor({ color: '#888', tabId: details.tabId });
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  removeTabData(tabId);
  tabLocks.delete(tabId);
  clearTimeout(badgeSettleTimers.get(tabId));
  badgeSettleTimers.delete(tabId);
});
