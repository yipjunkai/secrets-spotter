// content.js (ISOLATED world): relays intercepted payloads + DOM scans to the
// worker, handles SPA navigation, re-arms on bfcache restore, tears down on
// pagehide / context invalidation, and debounces MutationObserver activity.
import { afterEach, beforeEach, describe, it, expect, vi } from 'vitest';
import { createChrome } from './helpers/chrome.js';
import { createEnv, loadContentScript } from './helpers/loadScript.js';

const ORIGIN = 'https://app.example.test';

// Let pending microtasks (the async SHA-256 hash inside sendForScan) settle.
const flush = async (n = 4) => {
  for (let i = 0; i < n; i += 1) await new Promise((r) => setTimeout(r, 0));
};

// Build an incoming window message event with the source/origin the script
// requires (`event.source === window`, `event.origin === location.origin`).
function incoming(env, data) {
  return { source: env.window, origin: ORIGIN, data };
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

    const scanned = sentMessages(chrome).filter((m) => m.type === 'SCAN_TEXT');
    expect(scanned.some((m) => m.text.includes('mutation-added-unique-text'))).toBe(
      true,
    );
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
