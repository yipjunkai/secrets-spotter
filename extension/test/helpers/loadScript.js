// Loads the extension's classic-script IIFEs (content/interceptor.js,
// content/content.js) into a fresh, isolated happy-dom `Window` per test.
//
// The scripts run at document_start / document_idle in a real browser and
// reference globals (window, document, chrome, WebSocket, ...). We execute the
// source via `new Function(...globals, src)` so every bare global resolves to an
// injected, controllable value — giving perfect per-test isolation (no shared
// global state) without modifying the shipped code.
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Window } from 'happy-dom';
import { vi } from 'vitest';

const EXT_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');

// Deterministic, microtask-resolving stand-in for crypto.subtle.digest. Real
// SubtleCrypto hashes off-thread, so its promise never settles under fake
// timers (advanceTimersByTimeAsync) — which content.js's hash-dedup needs. This
// folds the input into a 32-byte digest: distinct content -> distinct output
// (so dedup still distinguishes texts), resolved on a plain microtask.
const fakeCrypto = {
  subtle: {
    digest: async (_algo, data) => {
      const bytes = new Uint8Array(data);
      const out = new Uint8Array(32);
      let h = 0x811c9dc5; // FNV-1a offset basis
      for (let i = 0; i < bytes.length; i += 1) {
        h = (h ^ bytes[i]) >>> 0;
        h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0;
        out[i % 32] = (out[i % 32] ^ (h & 0xff)) & 0xff;
      }
      out[0] = (out[0] ^ (bytes.length & 0xff)) & 0xff;
      return out.buffer;
    },
  },
};

// Minimal header bag mimicking fetch `Headers` (case-insensitive get + entries).
function makeHeaders(map = {}) {
  const m = new Map(
    Object.entries(map).map(([k, v]) => [k.toLowerCase(), String(v)]),
  );
  return {
    get: (k) => (m.has(k.toLowerCase()) ? m.get(k.toLowerCase()) : null),
    entries: () => m.entries(),
    [Symbol.iterator]: () => m.entries(),
  };
}

// A ReadableStream that emits `text` (UTF-8) in fixed-size chunks. `stats`
// records bytes pulled / cancellation so a test can prove the reader stopped
// early instead of draining the whole body.
function makeBodyStream(text, chunkSize, stats) {
  const bytes = new TextEncoder().encode(text);
  let offset = 0;
  return new ReadableStream({
    pull(controller) {
      if (offset >= bytes.length) {
        controller.close();
        return;
      }
      const end = Math.min(offset + chunkSize, bytes.length);
      controller.enqueue(bytes.slice(offset, end));
      if (stats) stats.bytesPulled += end - offset;
      offset = end;
    },
    cancel() {
      if (stats) stats.cancelled = true;
    },
  });
}

// Fake Response covering what interceptor.js reads: headers.get/entries, a
// streamed `body` (getReader), clone(), and text(). Each clone() gets its own
// stream (sharing `stats`), mirroring real clone semantics.
export function makeResponse(
  body = '',
  { headers = {}, stream = true, chunkSize = 65536, stats = null } = {},
) {
  const h = makeHeaders(headers);
  const make = () => ({
    headers: h,
    body: stream ? makeBodyStream(body, chunkSize, stats) : null,
    clone: () => make(),
    text: async () => body,
  });
  return make();
}

// Instrumented streaming response: returns { response, stats } so a test can
// assert how many bytes the interceptor's reader actually pulled.
export function makeStreamResponse(body, opts = {}) {
  const stats = { bytesPulled: 0, cancelled: false };
  return { response: makeResponse(body, { ...opts, stream: true, stats }), stats };
}

// Fake WebSocket / EventSource constructor the interceptor wraps. Instances are
// recorded so a test can grab one and `.dispatch('message', {data})`.
function makeFakeSocketClass(name, closedVal) {
  class FakeSocket {
    constructor(url, protocols) {
      this.url = url;
      this.protocols = protocols;
      this.readyState = 0;
      this._listeners = {};
      FakeSocket.instances.push(this);
    }

    addEventListener(type, fn) {
      (this._listeners[type] ||= new Set()).add(fn);
    }

    removeEventListener(type, fn) {
      this._listeners[type]?.delete(fn);
    }

    dispatch(type, event = {}) {
      for (const fn of [...(this._listeners[type] || [])]) fn(event);
    }

    close() {
      this.readyState = closedVal;
    }

    send() {}
  }
  FakeSocket.instances = [];
  FakeSocket.CONNECTING = 0;
  FakeSocket.OPEN = 1;
  FakeSocket.CLOSING = 2;
  FakeSocket.CLOSED = closedVal;
  Object.defineProperty(FakeSocket, 'name', { value: name });
  return FakeSocket;
}

class StubXHR {
  open() {}
  send() {}
  addEventListener() {}
  getAllResponseHeaders() {
    return '';
  }

  getResponseHeader() {
    return null;
  }
}

/**
 * Build a fresh window + controllable globals for one test.
 * Returns the window plus spies/affordances:
 *   posted            — vi.fn capturing window.postMessage
 *   fetchMock         — vi.fn behind window.fetch
 *   WebSocket/EventSource — fake classes (`.instances`)
 *   mutationObservers — fake MutationObserver instances (`.cb(mutations)`)
 *   emit(type, event) — invoke window listeners of `type`
 *   handlers(type)    — list window listeners of `type`
 */
export function createEnv({ url = 'https://app.example.test/page' } = {}) {
  const window = new Window({ url });
  const { document } = window;

  // Record listeners so tests fire synthetic events deterministically.
  const registry = new Map(); // target -> Map(type -> Set(fn))
  const instrument = (target) => {
    const origAdd = target.addEventListener?.bind(target);
    const origRemove = target.removeEventListener?.bind(target);
    target.addEventListener = (type, fn, opts) => {
      let byType = registry.get(target);
      if (!byType) registry.set(target, (byType = new Map()));
      (byType.get(type) ?? byType.set(type, new Set()).get(type)).add(fn);
      return origAdd?.(type, fn, opts);
    };
    target.removeEventListener = (type, fn, opts) => {
      registry.get(target)?.get(type)?.delete(fn);
      return origRemove?.(type, fn, opts);
    };
  };
  instrument(window);

  const posted = vi.fn();
  window.postMessage = posted;

  const fetchMock = vi.fn(async () => makeResponse(''));
  window.fetch = fetchMock;

  const WebSocket = makeFakeSocketClass('WebSocket', 3);
  const EventSource = makeFakeSocketClass('EventSource', 2);
  window.WebSocket = WebSocket;
  window.EventSource = EventSource;

  const mutationObservers = [];
  class MutationObserver {
    constructor(cb) {
      this.cb = cb;
      this.observe = vi.fn();
      this.disconnect = vi.fn();
      this.takeRecords = vi.fn(() => []);
      mutationObservers.push(this);
    }
  }

  const emit = (type, event = {}, target = window) => {
    const set = registry.get(target)?.get(type);
    if (!set) return false;
    for (const fn of [...set]) fn(event);
    return true;
  };
  const handlers = (type, target = window) => [
    ...(registry.get(target)?.get(type) || []),
  ];

  return {
    window,
    document,
    posted,
    fetchMock,
    WebSocket,
    EventSource,
    MutationObserver,
    mutationObservers,
    emit,
    handlers,
  };
}

/** Execute a content-script IIFE inside the given env, injecting `chrome`. */
export function loadContentScript(relPath, env, { chrome } = {}) {
  const src = readFileSync(resolve(EXT_DIR, relPath), 'utf8');
  const inject = {
    window: env.window,
    document: env.document,
    history: env.window.history,
    location: env.window.location,
    chrome,
    XMLHttpRequest: env.window.XMLHttpRequest ?? StubXHR,
    WebSocket: env.WebSocket,
    EventSource: env.EventSource,
    MutationObserver: env.MutationObserver,
    Node: env.window.Node,
    TextEncoder: globalThis.TextEncoder,
    TextDecoder: globalThis.TextDecoder,
    Headers: env.window.Headers ?? globalThis.Headers,
    // Node's Request (undici) — tests construct Request inputs with the same
    // constructor so the interceptor's instanceof check matches.
    Request: globalThis.Request ?? env.window.Request,
    Event: env.window.Event ?? globalThis.Event,
    AbortController: globalThis.AbortController,
    crypto: fakeCrypto,
    setTimeout: globalThis.setTimeout,
    clearTimeout: globalThis.clearTimeout,
    setInterval: globalThis.setInterval,
    clearInterval: globalThis.clearInterval,
    queueMicrotask: globalThis.queueMicrotask,
    console,
  };
  // eslint-disable-next-line no-new-func
  const fn = new Function(...Object.keys(inject), src);
  fn(...Object.values(inject));
  return env;
}
