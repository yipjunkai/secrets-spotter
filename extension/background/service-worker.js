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

// ── External-bundle scanning (SCAN_EXTERNAL) ─────────────────────────────────
// Fetch first-party <script src> from the worker, which (unlike a MAIN-world
// re-fetch) isn't bound by the page's CSP and already holds <all_urls> host
// permission. Cache findings per URL so a bundle shared across pages/tabs is
// fetched once; bound the cache, the per-page fetch count, and the read size.
const externalScanCache = new Map(); // url -> SecretFinding[]
const MAX_EXTERNAL_CACHE = 200;
const MAX_EXTERNAL_PER_PAGE = 20;
const EXTERNAL_FETCH_TIMEOUT_MS = 10_000;
const MAX_EXTERNAL_BYTES = 2_000_000; // matches the 2 MB scan cap

function cacheExternal(url, findings) {
  if (externalScanCache.size >= MAX_EXTERNAL_CACHE) {
    // Evict the oldest entry (Map preserves insertion order).
    externalScanCache.delete(externalScanCache.keys().next().value);
  }
  externalScanCache.set(url, findings);
}

// Fetch a URL with a timeout and no credentials, capping the read at the scan
// size so a huge bundle can't be pulled in full. Returns the (possibly
// truncated) body text, or '' on a non-OK response.
async function fetchCapped(url) {
  const signal = (typeof AbortSignal !== 'undefined' && AbortSignal.timeout)
    ? AbortSignal.timeout(EXTERNAL_FETCH_TIMEOUT_MS)
    : undefined;
  const res = await fetch(url, { signal, credentials: 'omit', redirect: 'follow' });
  if (!res.ok) return '';

  const reader = res.body?.getReader?.();
  if (!reader) {
    const text = await res.text();
    return text.length > MAX_EXTERNAL_BYTES ? text.slice(0, MAX_EXTERNAL_BYTES) : text;
  }
  const decoder = new TextDecoder();
  let out = '';
  while (out.length < MAX_EXTERNAL_BYTES) {
    const { done, value } = await reader.read();
    if (done) break;
    out += decoder.decode(value, { stream: true });
  }
  try { await reader.cancel(); } catch { /* already closed */ }
  return out.length > MAX_EXTERNAL_BYTES ? out.slice(0, MAX_EXTERNAL_BYTES) : out;
}

// Merge a scan's findings into a tab's record: drop stale-document scans,
// dedupe via Rust merge_findings, bump counts, and refresh the badge. Shared by
// the SCAN_TEXT relay and the SCAN_EXTERNAL bundle fetcher.
async function mergeIntoTab(tabId, sender, findings, source, url) {
  await withTabLock(tabId, async () => {
    const tabData = await getTabData(tabId);

    // Drop scans from a document that a later navigation already superseded.
    if (tabData.documentId && sender.documentId &&
        tabData.documentId !== sender.documentId) {
      return;
    }

    tabData.url = tabData.url || url;
    tabData.findings = merge_findings(tabData.findings, findings);
    tabData.scanned = (tabData.scanned || 0) + 1;
    tabData.lastScanTs = Date.now();
    tabData.sources = tabData.sources || {};
    tabData.sources[source] = (tabData.sources[source] || 0) + 1;

    await setTabData(tabId, tabData);
    updateBadge(tabId, significantCount(tabData.findings));
  });
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
        for (const f of newFindings) {
          f.source = message.source || 'unknown';
          f.sourceUrl = message.url || '';
        }
        await mergeIntoTab(tabId, sender, newFindings, source, message.url);
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

  if (message.type === 'SCAN_EXTERNAL') {
    const tabId = sender.tab?.id;
    const urls = Array.isArray(message.urls)
      ? message.urls.filter((u) => typeof u === 'string' && /^https?:/i.test(u))
      : [];
    initWasm().then(async () => {
      let budget = MAX_EXTERNAL_PER_PAGE;
      let capped = 0;
      const seen = new Set();

      await Promise.all(urls.map(async (url) => {
        if (seen.has(url)) return;
        seen.add(url);
        // should_scan reuses the CDN-host / media / library skip lists, so a
        // bundle from cdnjs/unpkg/etc. is never fetched — only first-party JS.
        if (!should_scan(url, '')) return;
        if (budget <= 0) { capped += 1; return; }
        budget -= 1;

        let findings = externalScanCache.get(url);
        if (!findings) {
          let body;
          try {
            body = await fetchCapped(url);
          } catch (err) {
            appendToLog(logEntry('service-worker', `external fetch failed: ${err.message}`, err.stack, url));
            return;
          }
          if (!body || body.length < 10) {
            cacheExternal(url, []);
            return;
          }
          findings = scan_text(body);
          for (const f of findings) {
            f.source = 'script';
            f.sourceUrl = url;
          }
          cacheExternal(url, findings);
        }

        if (findings.length > 0 && tabId != null) {
          await mergeIntoTab(tabId, sender, findings, 'script', url);
        }
      }));

      if (capped > 0) {
        appendToLog(logEntry('service-worker',
          `external scan hit the ${MAX_EXTERNAL_PER_PAGE}-script/page budget; skipped ${capped}`,
          null, message.url));
      }
      sendResponse({ ok: true });
    }).catch((err) => {
      appendToLog(logEntry('service-worker', `external scan failed: ${err.message}`, err.stack));
      sendResponse({ ok: false });
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
