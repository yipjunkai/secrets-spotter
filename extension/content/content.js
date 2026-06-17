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
  // Hash-based cache to skip already-scanned text (capped to prevent unbounded growth on SPAs)
  const scannedHashes = new Set();
  const MAX_HASHES = 500;
  const MAX_SCAN_SIZE = 2_000_000; // 2MB — matches WASM cap in lib.rs
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
    return document.documentElement.outerHTML || '';
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

    // Truncate to match WASM scan cap — avoids hashing/sending oversized text
    if (text.length > MAX_SCAN_SIZE) {
      text = text.slice(0, MAX_SCAN_SIZE);
    }

    const hash = await hashText(text);
    if (scannedHashes.has(hash)) return;
    if (scannedHashes.size >= MAX_HASHES) {
      scannedHashes.clear();
    }
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
          // Highlighting disabled
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

  // OAuth implicit-flow tokens land in the URL fragment (#access_token=…) and
  // query strings carry tokens too; the URL is otherwise only used as scan
  // metadata, never scanned as text.
  function scanUrl() {
    let href = window.location.href;
    try {
      href = decodeURIComponent(href);
    } catch {
      /* malformed %-escape — fall back to the raw href */
    }
    sendForScan(href, window.location.href, 'url');
  }

  // localStorage / sessionStorage are where SPAs stash JWTs, OAuth tokens, and
  // API keys. content.js (ISOLATED world) shares the page origin's storage, so
  // read it synchronously and route the key/value pairs through the same
  // structured path as data-* attributes (format_attributes in the worker).
  function scanStorage(store, source) {
    const pairs = [];
    try {
      for (let i = 0; i < store.length; i += 1) {
        const key = store.key(i);
        const value = store.getItem(key);
        if (value && value.length >= 8) {
          pairs.push({ name: key, value });
        }
      }
    } catch {
      return; // storage access can throw when partitioned or disabled
    }
    if (pairs.length > 0) {
      sendForScan(JSON.stringify(pairs), window.location.href, source);
    }
  }

  // External JS bundles are a top secret-leak surface (hardcoded keys in config
  // objects, keys used only inside a Worker, etc.) that the network interceptor
  // misses unless the page later *uses* the key in an intercepted call. We
  // collect <script src> URLs and let the SERVICE WORKER fetch + scan them: the
  // worker isn't bound by the page's CSP (a MAIN-world re-fetch is) and already
  // holds <all_urls> host permission. Default on; the future options page will
  // gate this. Set to false to disable.
  const SCAN_EXTERNAL_RESOURCES = true;

  function scanExternalScripts() {
    if (!SCAN_EXTERNAL_RESOURCES || !isContextValid()) return;
    let urls;
    try {
      urls = [...document.querySelectorAll('script[src]')]
        .map((s) => s.src)
        .filter((u) => /^https?:/i.test(u)); // skip data:/blob:/extension URLs
    } catch {
      return;
    }
    if (urls.length === 0) return;
    try {
      chrome.runtime.sendMessage({
        type: 'SCAN_EXTERNAL',
        urls,
        url: window.location.href,
      });
    } catch {
      /* extension context destroyed */
    }
  }

  // Defer the synchronous DOM serialization (outerHTML) + full-tree attribute
  // walk off the critical path: on a large page these block the main thread,
  // and on load/navigation that stall is user-visible. requestIdleCallback runs
  // them when the page is idle (timeout-bounded so a busy page still scans);
  // setTimeout is the fallback where it's unavailable.
  const scheduleIdle = window.requestIdleCallback
    ? (cb) => window.requestIdleCallback(cb, { timeout: 2000 })
    : (cb) => setTimeout(cb, 0);

  function scanPage() {
    scheduleIdle(() => {
      sendForScan(getPageSource(), window.location.href, 'dom');
      const structured = extractStructuredSecrets();
      if (structured) {
        sendForScan(structured, window.location.href, 'dom:structured');
      }
      scanUrl();
      scanStorage(window.localStorage, 'storage:local');
      scanStorage(window.sessionStorage, 'storage:session');
      scanExternalScripts();
    });
  }

  // Per-load nonce shared with the MAIN-world interceptor through the READY
  // handshake below; every relayed message must carry it. This is a real but
  // PARTIAL defense: page scripts share the interceptor's MAIN-world realm and
  // can observe the handshake, so a fully-malicious first-party page can still
  // learn the nonce and forge. What it does stop is the common case — unrelated
  // third-party scripts, or accidental collisions, blindly posting
  // `__SECRETS_SPOTTER_*` window messages. The service worker (which the page
  // cannot reach) remains the authoritative trust boundary.
  const RELAY_NONCE =
    typeof crypto !== 'undefined' && crypto.randomUUID
      ? crypto.randomUUID()
      : `${Date.now()}-${Math.random().toString(36).slice(2)}`;

  // Listen for intercepted network responses from the MAIN world script
  window.addEventListener('message', (event) => {
    if (event.source !== window) return;
    if (event.origin !== window.location.origin) return;
    if (event.data?.nonce !== RELAY_NONCE) return; // drop un-nonced / forged messages

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

  // Tell the MAIN-world interceptor we're listening — and hand it the nonce — so
  // it can flush any traffic it captured before this (later-injected) relay was ready.
  window.postMessage(
    { type: '__SECRETS_SPOTTER_READY__', nonce: RELAY_NONCE },
    window.location.origin,
  );

  if (document.readyState === 'complete') {
    scanPage();
  } else {
    window.addEventListener('load', () => scanPage());
  }

  let pendingTexts = [];
  let pendingBytes = 0;
  let maxWaitTimer = null;
  const MAX_PENDING_BYTES = 512_000; // flush early once this much text queues
  const FLUSH_DEBOUNCE = 2000;
  const MAX_FLUSH_WAIT = 10_000; // hard cap so continuous mutation can't starve the flush

  function flushPending() {
    clearTimeout(scanTimeout);
    scanTimeout = null;
    clearTimeout(maxWaitTimer);
    maxWaitTimer = null;
    if (pendingTexts.length === 0) return;
    const combined = pendingTexts.join('\n');
    pendingTexts = [];
    pendingBytes = 0;
    if (combined.length > 0) {
      sendForScan(combined, window.location.href, 'dom');
    }
  }

  observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node.nodeType === Node.ELEMENT_NODE || node.nodeType === Node.TEXT_NODE) {
          const text = node.textContent;
          if (text && text.length >= 10) {
            pendingTexts.push(text);
            pendingBytes += text.length;
          }
        }
      }
    }
    if (pendingTexts.length === 0) return;

    // Byte budget hit — flush now rather than queue text unbounded. (sendForScan
    // separately caps a single oversized node at MAX_SCAN_SIZE.)
    if (pendingBytes >= MAX_PENDING_BYTES) {
      flushPending();
      return;
    }

    // Debounce coalesces bursts; a non-resetting max-wait timer caps total
    // latency so a page mutating faster than the debounce can't starve it.
    clearTimeout(scanTimeout);
    scanTimeout = setTimeout(flushPending, FLUSH_DEBOUNCE);
    if (!maxWaitTimer) {
      maxWaitTimer = setTimeout(flushPending, MAX_FLUSH_WAIT);
    }
  });

  function observeDom() {
    const target = document.body || document.documentElement;
    if (target && observer) {
      observer.observe(target, { childList: true, subtree: true });
    }
  }
  observeDom();

  // Detect extension context invalidation (e.g. extension update/reload).
  function contextInvalidationTick() {
    if (typeof chrome === 'undefined' || !chrome.runtime?.id) {
      clearInterval(contextCheckInterval);
      contextCheckInterval = null;
      if (observer) observer.disconnect();
      clearTimeout(scanTimeout);
      clearTimeout(maxWaitTimer);
      maxWaitTimer = null;
      pendingTexts = [];
      pendingBytes = 0;
      // Signal MAIN world interceptor to clean up too
      window.dispatchEvent(new Event('__SECRETS_SPOTTER_CLEANUP__'));
    }
  }
  let contextCheckInterval = setInterval(contextInvalidationTick, 5000);

  window.addEventListener('pagehide', () => {
    // Entering bfcache or unloading — tear down. pageshow re-arms on a bfcache
    // restore (when this script's context is resumed rather than re-run).
    clearInterval(contextCheckInterval);
    contextCheckInterval = null;
    if (observer) observer.disconnect();
    clearTimeout(scanTimeout);
    clearTimeout(maxWaitTimer);
    maxWaitTimer = null;
    pendingTexts = [];
    pendingBytes = 0;
  });

  window.addEventListener('pageshow', (event) => {
    if (!event.persisted) return; // fresh loads are already armed at injection
    // Restored from bfcache: the back/forward navigation made the worker clear
    // this tab's findings, but this content script never re-ran — so re-arm the
    // observer and re-scan (clearing the hash cache so the re-scan isn't skipped).
    if (!contextCheckInterval) {
      contextCheckInterval = setInterval(contextInvalidationTick, 5000);
    }
    observeDom();
    scannedHashes.clear();
    scanPage();
  });
})();
