import init, {
  scan_text,
  pattern_count,
  should_scan,
  parse_cookies,
  format_attributes,
  merge_findings,
} from '../wasm/secrets_spotter_wasm.js';

let wasmReady = false;
let wasmInitPromise = null;

const MAX_LOG_ENTRIES = 100;

// Serialize error-log writes through one promise chain. Without it, concurrent
// appendToLog() calls each do get -> modify -> set and clobber one another
// (a read-modify-write race in the worker).
let logWriteChain = Promise.resolve();
function appendToLog(entry) {
  logWriteChain = logWriteChain.then(async () => {
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
  });
  return logWriteChain;
}

// Strip query strings and fragments from logged URLs — they can carry tokens or
// PII that shouldn't be persisted in the (user-visible) debug log.
function stripUrl(url) {
  if (!url) return null;
  try {
    const u = new URL(url);
    return `${u.origin}${u.pathname}`;
  } catch {
    return null;
  }
}

function logEntry(src, msg, stack, url) {
  return { ts: Date.now(), src, msg, stack: stack || null, url: stripUrl(url) };
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
      const wasmUrl = chrome.runtime.getURL('wasm/secrets_spotter_wasm_bg.wasm');
      await init(wasmUrl);
      wasmReady = true;
      console.log(`Secrets Spotter WASM loaded. ${pattern_count()} patterns active.`);
    } catch (err) {
      // Allow retry after cooldown, but prevent thundering herd
      setTimeout(() => { wasmInitPromise = null; }, 5000);
      throw err;
    }
  })();
  return wasmInitPromise;
}

const badgeSettleTimers = new Map();

// Fallback timers that clear the "..." loading badge if no scan ever completes
// for a tab (a page with no DOM/network activity, or where content.js failed to
// inject) — otherwise the badge sticks on "..." forever.
const loadingBadgeTimers = new Map();
const LOADING_BADGE_TIMEOUT = 8000;

function clearLoadingBadge(tabId) {
  const timer = loadingBadgeTimers.get(tabId);
  if (timer) {
    clearTimeout(timer);
    loadingBadgeTimers.delete(tabId);
  }
}

function significantCount(findings) {
  return findings.filter(f => f.severity === 'Critical' || f.severity === 'High').length;
}

function updateBadge(tabId, count) {
  // A scan completed, so the tab is past "loading" — cancel the fallback timer.
  clearLoadingBadge(tabId);
  if (count > 0) {
    // Immediately show the count
    clearTimeout(badgeSettleTimers.get(tabId));
    badgeSettleTimers.delete(tabId);
    chrome.action.setBadgeText({ text: String(count), tabId }).catch(() => {});
    chrome.action.setBadgeBackgroundColor({ color: '#e74c3c', tabId }).catch(() => {});
  } else {
    // Delay clearing "..." so it doesn't flash away between scan chunks.
    // If no findings arrive within 3s of the last scan, clear the badge.
    if (badgeSettleTimers.has(tabId)) return;
    const timer = setTimeout(() => {
      badgeSettleTimers.delete(tabId);
      chrome.action.setBadgeText({ text: '', tabId }).catch(() => {});
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
  return result[key] || { findings: [], url: '', scanned: 0, skipped: 0, sources: {}, documentId: null };
}

async function setTabData(tabId, data) {
  try {
    await chrome.storage.session.set({ [tabKey(tabId)]: data });
  } catch (err) {
    appendToLog(logEntry('service-worker', `setTabData failed (quota?): ${err.message}`, err.stack));
    // Attempt recovery: truncate findings to reduce storage size
    if (data.findings && data.findings.length > 50) {
      data.findings = data.findings.slice(0, 50);
      try {
        await chrome.storage.session.set({ [tabKey(tabId)]: data });
      } catch {
        data.findings = [];
        await chrome.storage.session.set({ [tabKey(tabId)]: data }).catch(() => {});
      }
    }
  }
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
  if (source.startsWith('storage:')) return 'storage'; // storage:local / :session / :idb
  if (source === 'url') return 'url';
  // network:fetch, network:xhr, network:websocket, network:sse, etc.
  const match = source.match(/^network:(?:request:|header:)?(.+)$/);
  return match ? match[1] : source;
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'CLEAR_DOM_FINDINGS') {
    const tabId = sender.tab?.id;
    if (tabId != null) {
      withTabLock(tabId, async () => {
        const tabData = await getTabData(tabId);
        tabData.findings = tabData.findings.filter(f => f.source && f.source !== 'dom' && f.source !== 'dom:structured');
        await setTabData(tabId, tabData);
        updateBadge(tabId, significantCount(tabData.findings));
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
      } else if (
        message.source === 'dom:structured' ||
        message.source === 'storage:local' ||
        message.source === 'storage:session'
      ) {
        // Storage entries are key/value pairs, same shape as data-* attributes.
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

          // Drop scans from a document that a later navigation already
          // superseded, so stale findings aren't attributed to the new page.
          if (tabData.documentId && sender.documentId &&
              tabData.documentId !== sender.documentId) {
            return;
          }

          tabData.url = tabData.url || message.url;

          // Deduplicate via Rust
          tabData.findings = merge_findings(tabData.findings, newFindings);

          tabData.scanned = (tabData.scanned || 0) + 1;
          tabData.lastScanTs = Date.now();
          tabData.sources = tabData.sources || {};
          tabData.sources[source] = (tabData.sources[source] || 0) + 1;

          await setTabData(tabId, tabData);
          updateBadge(tabId, significantCount(tabData.findings));
        });
      }

      // The content script discards this response (it only checks lastError),
      // so don't echo the full findings array back across the message boundary.
      sendResponse({ ok: true });
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
  if (details.frameId !== 0) return;
  const tabId = details.tabId;

  // Reset to a fresh record stamped with the new document's id; scans that
  // arrive late from the previous document are dropped in the SCAN_TEXT handler.
  withTabLock(tabId, () =>
    setTabData(tabId, {
      findings: [], url: '', scanned: 0, skipped: 0,
      sources: {}, documentId: details.documentId,
    })
  );

  clearTimeout(badgeSettleTimers.get(tabId));
  badgeSettleTimers.delete(tabId);
  chrome.action.setBadgeText({ text: '...', tabId }).catch(() => {});
  chrome.action.setBadgeBackgroundColor({ color: '#888', tabId }).catch(() => {});

  // Clear the loading badge if no scan completes within the timeout.
  clearLoadingBadge(tabId);
  loadingBadgeTimers.set(tabId, setTimeout(() => {
    loadingBadgeTimers.delete(tabId);
    chrome.action.setBadgeText({ text: '', tabId }).catch(() => {});
  }, LOADING_BADGE_TIMEOUT));
});

chrome.tabs.onRemoved.addListener((tabId) => {
  removeTabData(tabId);
  tabLocks.delete(tabId);
  clearTimeout(badgeSettleTimers.get(tabId));
  badgeSettleTimers.delete(tabId);
  clearLoadingBadge(tabId);
});
