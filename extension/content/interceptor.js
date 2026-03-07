// Runs in MAIN world to intercept all text-based content the browser receives.
// Patches fetch(), XMLHttpRequest, WebSocket, and EventSource.
// Also re-fetches external <script> and <link> files.
// Posts captured text back to the content script via window.postMessage.
(function () {
  'use strict';

  const MAX_SIZE = 2_000_000; // 2MB cap
  const BATCH_INTERVAL = 2000; // 2s flush for streaming sources

  const SKIP_EXTENSIONS = /\.(png|jpg|jpeg|gif|svg|ico|webp|bmp|tiff|avif|woff2?|ttf|eot|otf|mp3|mp4|webm|ogg|wav|avi|mov|pdf|zip|tar|gz|br|map|wasm)(\?|$)/i;

  const SKIP_CONTENT_TYPES = /^(image|audio|video|font)\//i;

  const SKIP_PATHS = /\/(jquery|lodash|react|angular|vue|bootstrap|tailwind|fontawesome|googleapis|cdn|polyfill|analytics|gtag|gtm)\b/i;

  const SKIP_CDN_HOSTS = /^https?:\/\/(cdnjs\.cloudflare\.com|unpkg\.com|cdn\.jsdelivr\.net|ajax\.googleapis\.com|cdn\.bootcdn\.net|code\.jquery\.com|stackpath\.bootstrapcdn\.com|maxcdn\.bootstrapcdn\.com|fonts\.googleapis\.com|use\.fontawesome\.com|cdn\.tailwindcss\.com)/i;

  function shouldScan(url, contentType) {
    if (SKIP_EXTENSIONS.test(url)) return false;
    if (SKIP_PATHS.test(url)) return false;
    if (contentType && SKIP_CONTENT_TYPES.test(contentType)) return false;
    return true;
  }

  function postIntercepted(url, body, source) {
    if (!body || typeof body !== 'string' || body.length < 10) return;
    const text = body.length > MAX_SIZE ? body.slice(0, MAX_SIZE) : body;
    window.postMessage({
      type: '__SECRETS_SPOTTER_INTERCEPT__',
      url,
      text,
      source,
    }, '*');
  }

  // =========================================================================
  // 1. Patch fetch() — request + response headers & body
  // =========================================================================
  const originalFetch = window.fetch;
  window.fetch = async function (...args) {
    // Scan outgoing request headers and body
    try {
      const url = (typeof args[0] === 'string' ? args[0] : args[0]?.url) || '';
      const opts = args[1] || {};

      // Request headers
      if (opts.headers) {
        const headerLines = [];
        if (opts.headers instanceof Headers) {
          for (const [name, value] of opts.headers.entries()) {
            headerLines.push(`${name}: ${value}`);
          }
        } else if (typeof opts.headers === 'object') {
          for (const [name, value] of Object.entries(opts.headers)) {
            headerLines.push(`${name}: ${value}`);
          }
        }
        if (headerLines.length > 0) {
          postIntercepted(url, headerLines.join('\n'), 'request:fetch');
        }
      }

      // Request body
      if (typeof opts.body === 'string' && opts.body.length >= 10) {
        postIntercepted(url, opts.body, 'request:fetch');
      }
    } catch {}

    const response = await originalFetch.apply(this, args);
    try {
      const url = (typeof args[0] === 'string' ? args[0] : args[0]?.url) || '';
      const contentType = response.headers.get('content-type') || '';

      if (shouldScan(url, contentType)) {
        // Scan response headers
        try {
          const headerLines = [];
          for (const [name, value] of response.headers.entries()) {
            headerLines.push(`${name}: ${value}`);
          }
          if (headerLines.length > 0) {
            postIntercepted(url, headerLines.join('\n'), 'header:fetch');
          }
        } catch {}

        // Scan response body
        const clone = response.clone();
        clone.text().then((body) => {
          postIntercepted(url, body, 'fetch');
        }).catch(() => {});
      }
    } catch {
      // Never break the page
    }
    return response;
  };

  // =========================================================================
  // 2. Patch XMLHttpRequest — body + headers
  // =========================================================================
  const XHROpen = XMLHttpRequest.prototype.open;
  const XHRSend = XMLHttpRequest.prototype.send;

  XMLHttpRequest.prototype.open = function (method, url, ...rest) {
    this.__ssUrl = typeof url === 'string' ? url : String(url);
    return XHROpen.call(this, method, url, ...rest);
  };

  XMLHttpRequest.prototype.send = function (...args) {
    // Scan outgoing request body
    try {
      const body = args[0];
      if (typeof body === 'string' && body.length >= 10) {
        postIntercepted(this.__ssUrl || '', body, 'request:xhr');
      }
    } catch {}

    this.addEventListener('load', function () {
      try {
        const contentType = this.getResponseHeader('content-type') || '';
        const url = this.__ssUrl || '';
        if (!shouldScan(url, contentType)) return;

        // Scan response body
        if (typeof this.responseText === 'string') {
          postIntercepted(url, this.responseText, 'xhr');
        }

        // Scan response headers
        try {
          const rawHeaders = this.getAllResponseHeaders();
          if (rawHeaders) {
            postIntercepted(url, rawHeaders, 'header:xhr');
          }
        } catch {}
      } catch {
        // Never break the page
      }
    });
    return XHRSend.apply(this, args);
  };

  // =========================================================================
  // 3. Patch WebSocket — batched string message interception
  // =========================================================================
  const OriginalWebSocket = window.WebSocket;
  if (OriginalWebSocket) {
    window.WebSocket = function (url, protocols) {
      const instance = protocols !== undefined
        ? new OriginalWebSocket(url, protocols)
        : new OriginalWebSocket(url);

      const resolvedUrl = typeof url === 'string' ? url : String(url);
      if (!shouldScan(resolvedUrl, '')) return instance;

      let buffer = [];
      let bufferSize = 0;
      let flushTimer = null;

      function flushBuffer() {
        if (buffer.length === 0) return;
        const combined = buffer.join('\n---WS_MSG---\n');
        buffer = [];
        bufferSize = 0;
        postIntercepted(resolvedUrl, combined, 'websocket');
      }

      instance.addEventListener('message', function (event) {
        try {
          const data = event.data;
          if (typeof data !== 'string' || data.length < 10) return;

          const text = data.length > MAX_SIZE ? data.slice(0, MAX_SIZE) : data;
          buffer.push(text);
          bufferSize += text.length;

          if (bufferSize > MAX_SIZE) {
            clearTimeout(flushTimer);
            flushTimer = null;
            flushBuffer();
            return;
          }

          if (!flushTimer) {
            flushTimer = setTimeout(() => {
              flushTimer = null;
              flushBuffer();
            }, BATCH_INTERVAL);
          }
        } catch {}
      });

      return instance;
    };

    window.WebSocket.prototype = OriginalWebSocket.prototype;
    window.WebSocket.CONNECTING = OriginalWebSocket.CONNECTING;
    window.WebSocket.OPEN = OriginalWebSocket.OPEN;
    window.WebSocket.CLOSING = OriginalWebSocket.CLOSING;
    window.WebSocket.CLOSED = OriginalWebSocket.CLOSED;
  }

  // =========================================================================
  // 4. Patch EventSource (SSE) — batched message interception
  // =========================================================================
  const OriginalEventSource = window.EventSource;
  if (OriginalEventSource) {
    window.EventSource = function (url, config) {
      const instance = new OriginalEventSource(url, config);
      const resolvedUrl = typeof url === 'string' ? url : String(url);

      if (!shouldScan(resolvedUrl, '')) return instance;

      let buffer = [];
      let bufferSize = 0;
      let flushTimer = null;

      function flushBuffer() {
        if (buffer.length === 0) return;
        const combined = buffer.join('\n---SSE_MSG---\n');
        buffer = [];
        bufferSize = 0;
        postIntercepted(resolvedUrl, combined, 'sse');
      }

      function onMessage(event) {
        try {
          const data = event.data;
          if (typeof data !== 'string' || data.length < 10) return;

          const text = data.length > MAX_SIZE ? data.slice(0, MAX_SIZE) : data;
          buffer.push(text);
          bufferSize += text.length;

          if (bufferSize > MAX_SIZE) {
            clearTimeout(flushTimer);
            flushTimer = null;
            flushBuffer();
            return;
          }

          if (!flushTimer) {
            flushTimer = setTimeout(() => {
              flushTimer = null;
              flushBuffer();
            }, BATCH_INTERVAL);
          }
        } catch {}
      }

      // Capture default 'message' events
      instance.addEventListener('message', onMessage);

      // Wrap addEventListener to also capture custom SSE event types
      const origAdd = instance.addEventListener.bind(instance);
      const hookedTypes = new Set(['message', 'open', 'error']);
      instance.addEventListener = function (type, listener, options) {
        origAdd(type, listener, options);
        if (!hookedTypes.has(type)) {
          hookedTypes.add(type);
          origAdd(type, onMessage);
        }
      };

      return instance;
    };

    window.EventSource.prototype = OriginalEventSource.prototype;
    window.EventSource.CONNECTING = OriginalEventSource.CONNECTING;
    window.EventSource.OPEN = OriginalEventSource.OPEN;
    window.EventSource.CLOSED = OriginalEventSource.CLOSED;
  }

  // =========================================================================
  // 5. Scan external <script src> and <link stylesheet> files
  // =========================================================================
  function scanExternalScripts() {
    const scripts = document.querySelectorAll('script[src]');
    const seen = new Set();

    for (const script of scripts) {
      const src = script.src;
      if (!src || seen.has(src)) continue;
      seen.add(src);
      if (SKIP_CDN_HOSTS.test(src)) continue;
      if (!shouldScan(src, '')) continue;

      // Use originalFetch to avoid triggering our own fetch() interceptor
      originalFetch(src, { credentials: 'include' })
        .then((res) => {
          if (!res.ok) return;
          const ct = res.headers.get('content-type') || '';
          if (ct && !ct.includes('javascript') && !ct.includes('text') && !ct.includes('json')) return;
          return res.text();
        })
        .then((body) => {
          if (body) postIntercepted(src, body, 'script');
        })
        .catch(() => {});
    }
  }

  function scanExternalStylesheets() {
    const links = document.querySelectorAll('link[rel="stylesheet"][href]');
    const seen = new Set();

    for (const link of links) {
      const href = link.href;
      if (!href || seen.has(href)) continue;
      seen.add(href);
      if (SKIP_CDN_HOSTS.test(href)) continue;
      if (!shouldScan(href, '')) continue;

      // Use originalFetch to avoid triggering our own fetch() interceptor
      originalFetch(href, { credentials: 'include' })
        .then((res) => {
          if (!res.ok) return;
          return res.text();
        })
        .then((body) => {
          if (body) postIntercepted(href, body, 'css');
        })
        .catch(() => {});
    }
  }

  // =========================================================================
  // 6. Scan cookies
  // =========================================================================
  function scanCookies() {
    const cookies = document.cookie;
    if (cookies && cookies.length >= 10) {
      postIntercepted(window.location.href, cookies, 'cookie');
    }
  }

  // Trigger after DOM is fully loaded so all script/link tags are present
  if (document.readyState === 'complete') {
    scanExternalScripts();
    scanExternalStylesheets();
    scanCookies();
  } else {
    window.addEventListener('load', () => {
      scanExternalScripts();
      scanExternalStylesheets();
      scanCookies();
    }, { once: true });
  }

  // =========================================================================
  // 7. SPA navigation detection — pushState, replaceState, popstate, hashchange
  // =========================================================================
  let lastUrl = window.location.href;

  function onNavigation() {
    const currentUrl = window.location.href;
    if (currentUrl === lastUrl) return;
    lastUrl = currentUrl;

    window.postMessage({
      type: '__SECRETS_SPOTTER_NAVIGATION__',
      url: currentUrl,
    }, '*');

    scanCookies();
  }

  const originalPushState = history.pushState;
  history.pushState = function (...args) {
    const result = originalPushState.apply(this, args);
    onNavigation();
    return result;
  };

  const originalReplaceState = history.replaceState;
  history.replaceState = function (...args) {
    const result = originalReplaceState.apply(this, args);
    onNavigation();
    return result;
  };

  window.addEventListener('popstate', () => onNavigation());
  window.addEventListener('hashchange', () => onNavigation());

})();
