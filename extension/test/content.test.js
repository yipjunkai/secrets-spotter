// content.js (ISOLATED world): relays intercepted payloads + DOM scans to the
// worker, handles SPA navigation, re-arms on bfcache restore, tears down on
// pagehide / context invalidation, and debounces MutationObserver activity.
import { afterEach, beforeEach, describe, it, expect, vi } from 'vitest';
import { createChrome } from './helpers/chrome.js';
import { createEnv, loadContentScript, FAKE_NONCE } from './helpers/loadScript.js';

const ORIGIN = 'https://app.example.test';

// Let pending microtasks (the async SHA-256 hash inside sendForScan) settle.
const flush = async (n = 4) => {
  for (let i = 0; i < n; i += 1) await new Promise((r) => setTimeout(r, 0));
};

// Build an incoming window message event with the source/origin/nonce the
// script requires (`event.source === window`, matching origin, and the relay
// nonce content.js minted — FAKE_NONCE in tests).
function incoming(env, data) {
  return { source: env.window, origin: ORIGIN, data: { ...data, nonce: FAKE_NONCE } };
}

const sentMessages = (chrome) =>
  chrome.runtime.sendMessage.mock.calls.map((c) => c[0]);

// Load content.js, let the load-time scan settle, then clear the message spy so
// each test asserts only the calls it triggers.
async function setup() {
  const env = createEnv({ url: `${ORIGIN}/page` });
  const chrome = createChrome();
  loadContentScript('content/content.js', env, { chrome });
  await flush();
  chrome.runtime.sendMessage.mockClear();
  return { env, chrome };
}

afterEach(() => vi.useRealTimers());

describe('content.js — relay', () => {
  it('announces READY and scans the page on load', async () => {
    const env = createEnv({ url: `${ORIGIN}/page` });
    const chrome = createChrome();
    loadContentScript('content/content.js', env, { chrome });

    const ready = env.posted.mock.calls.filter(
      ([m]) => m?.type === '__SECRETS_SPOTTER_READY__',
    );
    expect(ready).toHaveLength(1);

    await flush();
    expect(sentMessages(chrome).some((m) => m.type === 'SCAN_TEXT')).toBe(true);
  });

  it('relays an intercepted payload to the worker as SCAN_TEXT', async () => {
    const { env, chrome } = await setup();

    env.emit(
      'message',
      incoming(env, {
        type: '__SECRETS_SPOTTER_INTERCEPT__',
        url: `${ORIGIN}/api/data`,
        text: 'intercepted-response-body',
        source: 'fetch',
        contentType: 'application/json',
      }),
    );
    await flush();

    const scan = sentMessages(chrome).find((m) => m.type === 'SCAN_TEXT');
    expect(scan).toMatchObject({
      text: 'intercepted-response-body',
      url: `${ORIGIN}/api/data`,
      source: 'network:fetch',
      contentType: 'application/json',
    });
  });

  it('ignores messages from a foreign origin or a different source', async () => {
    const { env, chrome } = await setup();

    env.emit('message', {
      source: env.window,
      origin: 'https://evil.example',
      data: { type: '__SECRETS_SPOTTER_INTERCEPT__', text: 'x'.repeat(20), source: 'fetch' },
    });
    env.emit('message', {
      source: {},
      origin: ORIGIN,
      data: { type: '__SECRETS_SPOTTER_INTERCEPT__', text: 'x'.repeat(20), source: 'fetch' },
    });
    await flush();

    expect(sentMessages(chrome)).toHaveLength(0);
  });

  it('ignores same-origin messages without the relay nonce (forgery)', async () => {
    const { env, chrome } = await setup();

    // Correct source + origin, but no nonce / a guessed one — a page script
    // forging the relay protocol. Both are dropped.
    env.emit('message', {
      source: env.window,
      origin: ORIGIN,
      data: { type: '__SECRETS_SPOTTER_INTERCEPT__', text: 'forged-payload-aaaa', source: 'fetch' },
    });
    env.emit('message', {
      source: env.window,
      origin: ORIGIN,
      data: {
        type: '__SECRETS_SPOTTER_INTERCEPT__',
        text: 'forged-payload-bbbb',
        source: 'fetch',
        nonce: 'wrong-nonce',
      },
    });
    await flush();

    expect(sentMessages(chrome)).toHaveLength(0);
  });
});

describe('content.js — navigation (nav-race)', () => {
  it('clears DOM findings and rescans on SPA navigation', async () => {
    const { env, chrome } = await setup();

    env.emit(
      'message',
      incoming(env, { type: '__SECRETS_SPOTTER_NAVIGATION__', url: `${ORIGIN}/next` }),
    );
    await flush();

    const types = sentMessages(chrome).map((m) => m.type);
    expect(types).toContain('CLEAR_DOM_FINDINGS');
    expect(types).toContain('SCAN_TEXT'); // re-scan of the new page
  });
});

describe('content.js — bfcache', () => {
  it('re-scans when restored from bfcache (pageshow persisted)', async () => {
    const { env, chrome } = await setup();

    env.emit('pageshow', { persisted: true });
    await flush();

    expect(sentMessages(chrome).some((m) => m.type === 'SCAN_TEXT')).toBe(true);
  });

  it('does nothing for a normal pageshow (persisted: false)', async () => {
    const { env, chrome } = await setup();

    env.emit('pageshow', { persisted: false });
    await flush();

    expect(sentMessages(chrome)).toHaveLength(0);
  });

  it('disconnects the observer on pagehide', async () => {
    const { env } = await setup();
    env.emit('pagehide', {});
    expect(env.mutationObservers[0].disconnect).toHaveBeenCalled();
  });
});

describe('content.js — MutationObserver', () => {
  it('debounces added-node text into a single DOM scan', async () => {
    vi.useFakeTimers();
    const env = createEnv({ url: `${ORIGIN}/page` });
    const chrome = createChrome();
    loadContentScript('content/content.js', env, { chrome });
    await vi.advanceTimersByTimeAsync(0); // settle load-time scan
    chrome.runtime.sendMessage.mockClear();

    const observer = env.mutationObservers[0];
    observer.cb([
      { addedNodes: [{ nodeType: 1, textContent: 'mutation-added-unique-text' }] },
    ]);

    // Nothing yet — still inside the 2s debounce window.
    expect(sentMessages(chrome)).toHaveLength(0);

    await vi.advanceTimersByTimeAsync(2000);

    // The debounce callback fire-and-forgets sendForScan, which awaits an
    // async SHA-256 before chrome.runtime.sendMessage. The hash settles on
    // the threadpool, not the microtask queue, so fake-timer advancement
    // can't guarantee it has resolved — drain it on real time instead.
    // (Flaked on CI: runs 27395197996, 27395772334.)
    vi.useRealTimers();
    await flush();

    const scanned = sentMessages(chrome).filter((m) => m.type === 'SCAN_TEXT');
    expect(scanned.some((m) => m.text.includes('mutation-added-unique-text'))).toBe(
      true,
    );
  });
});

describe('content.js — capture bounding', () => {
  it('defers the DOM walk through an idle callback instead of running it inline', async () => {
    const env = createEnv({ url: `${ORIGIN}/page` });
    // Force a capturing requestIdleCallback (happy-dom exposes it as a
    // getter-only undefined stub, so defineProperty is required to shadow it).
    const idleCbs = [];
    Object.defineProperty(env.window, 'requestIdleCallback', {
      configurable: true,
      value: (cb) => idleCbs.push(cb),
    });
    const chrome = createChrome();
    loadContentScript('content/content.js', env, { chrome });
    env.emit('load'); // cover the case where the load scan waits on the load event

    // The heavy outerHTML + attribute walk was scheduled, not run inline.
    expect(idleCbs.length).toBeGreaterThan(0);
    expect(sentMessages(chrome).filter((m) => m.type === 'SCAN_TEXT')).toHaveLength(0);

    // Running the captured callback performs the deferred scan.
    idleCbs.forEach((cb) => cb({ didTimeout: false, timeRemaining: () => 50 }));
    await flush();
    expect(sentMessages(chrome).some((m) => m.type === 'SCAN_TEXT')).toBe(true);
  });

  it('flushes immediately when the pending byte budget is exceeded', async () => {
    vi.useFakeTimers();
    const env = createEnv({ url: `${ORIGIN}/page` });
    const chrome = createChrome();
    loadContentScript('content/content.js', env, { chrome });
    await vi.advanceTimersByTimeAsync(0); // settle the load scan
    chrome.runtime.sendMessage.mockClear();

    // A single added node larger than MAX_PENDING_BYTES (512 KB) → flush now,
    // without waiting out the 2s debounce.
    env.mutationObservers[0].cb([
      { addedNodes: [{ nodeType: 1, textContent: 'B'.repeat(600_000) }] },
    ]);
    await vi.advanceTimersByTimeAsync(0); // microtasks only, NOT the 2s debounce

    const scanned = sentMessages(chrome).filter((m) => m.type === 'SCAN_TEXT');
    expect(scanned.some((m) => m.text.length >= 500_000)).toBe(true);
  });

  it('flushes by the max-wait even while mutations keep resetting the debounce', async () => {
    vi.useFakeTimers();
    const env = createEnv({ url: `${ORIGIN}/page` });
    const chrome = createChrome();
    loadContentScript('content/content.js', env, { chrome });
    await vi.advanceTimersByTimeAsync(0);
    chrome.runtime.sendMessage.mockClear();

    const observer = env.mutationObservers[0];
    // A mutation every 1s — each resets the 2s debounce, so without the 10s
    // max-wait cap it would never flush.
    for (let i = 0; i < 12; i += 1) {
      observer.cb([
        { addedNodes: [{ nodeType: 1, textContent: `starve-tick-${i}-padding` }] },
      ]);
      await vi.advanceTimersByTimeAsync(1000);
    }

    expect(sentMessages(chrome).some((m) => m.type === 'SCAN_TEXT')).toBe(true);
  });
});

describe('content.js — context invalidation', () => {
  it('tears down the observer when the extension context goes away', async () => {
    vi.useFakeTimers();
    const env = createEnv({ url: `${ORIGIN}/page` });
    const chrome = createChrome();
    loadContentScript('content/content.js', env, { chrome });
    await vi.advanceTimersByTimeAsync(0);

    chrome.runtime.id = undefined; // simulate extension reload/disable
    await vi.advanceTimersByTimeAsync(5000); // context-check interval

    expect(env.mutationObservers[0].disconnect).toHaveBeenCalled();
  });
});

describe('content.js — storage & URL capture', () => {
  it('scans localStorage and sessionStorage on load', async () => {
    const env = createEnv({ url: `${ORIGIN}/page` });
    env.window.localStorage.setItem('auth_token', 'stored-localstorage-value-123');
    env.window.sessionStorage.setItem('csrf', 'stored-sessionstorage-value-456');
    const chrome = createChrome();
    loadContentScript('content/content.js', env, { chrome });
    await flush();

    const scans = sentMessages(chrome).filter((m) => m.type === 'SCAN_TEXT');
    const local = scans.find((m) => m.source === 'storage:local');
    const session = scans.find((m) => m.source === 'storage:session');

    expect(local).toBeTruthy();
    expect(local.text).toContain('auth_token');
    expect(local.text).toContain('stored-localstorage-value-123');
    expect(session).toBeTruthy();
    expect(session.text).toContain('csrf');
  });

  it('skips storage values below the 8-char floor', async () => {
    const env = createEnv({ url: `${ORIGIN}/page` });
    env.window.localStorage.setItem('k', 'short'); // < 8 chars → ignored
    const chrome = createChrome();
    loadContentScript('content/content.js', env, { chrome });
    await flush();

    const local = sentMessages(chrome).find((m) => m.source === 'storage:local');
    expect(local).toBeUndefined();
  });

  it('scans the URL fragment on load (OAuth implicit token)', async () => {
    // Benign marker (not a real token shape) — this test only proves the URL is
    // relayed for scanning; the detector itself is exercised in the core tests.
    const token = 'oauth-implicit-fragment-marker-1234567890';
    const env = createEnv({ url: `${ORIGIN}/callback#access_token=${token}` });
    const chrome = createChrome();
    loadContentScript('content/content.js', env, { chrome });
    await flush();

    const url = sentMessages(chrome).find((m) => m.source === 'url');
    expect(url).toBeTruthy();
    expect(url.text).toContain('access_token');
    expect(url.text).toContain(token);
  });
});

describe('content.js — external scripts', () => {
  it('collects <script src> URLs and asks the worker to scan them', async () => {
    const env = createEnv({ url: `${ORIGIN}/page` });
    const s = env.document.createElement('script');
    s.src = `${ORIGIN}/static/app.bundle.js`;
    env.document.head.appendChild(s);
    const chrome = createChrome();
    loadContentScript('content/content.js', env, { chrome });
    await flush();

    const ext = sentMessages(chrome).find((m) => m.type === 'SCAN_EXTERNAL');
    expect(ext).toBeTruthy();
    expect(ext.urls).toContain(`${ORIGIN}/static/app.bundle.js`);
  });

  it('sends no SCAN_EXTERNAL when the page has no external scripts', async () => {
    const env = createEnv({ url: `${ORIGIN}/page` });
    const chrome = createChrome();
    loadContentScript('content/content.js', env, { chrome });
    await flush();

    expect(sentMessages(chrome).some((m) => m.type === 'SCAN_EXTERNAL')).toBe(false);
  });
});
