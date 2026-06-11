// Validates the harness itself: the IIFEs load into a fresh window, bare globals
// resolve to injected values, and basic side effects are observable.
import { afterEach, describe, it, expect } from 'vitest';
import { createChrome } from './helpers/chrome.js';
import { createEnv, loadContentScript } from './helpers/loadScript.js';
import {
  loadServiceWorker,
  teardownServiceWorker,
} from './helpers/loadServiceWorker.js';

afterEach(teardownServiceWorker);

describe('harness smoke', () => {
  it('interceptor.js loads, patches window.fetch, and listens for messages', () => {
    const env = createEnv();
    const before = env.window.fetch;
    loadContentScript('content/interceptor.js', env, { chrome: createChrome() });

    expect(typeof env.window.fetch).toBe('function');
    expect(env.window.fetch).not.toBe(before); // fetch was wrapped
    expect(env.handlers('message').length).toBeGreaterThan(0); // relay-ready listener
  });

  it('content.js loads, announces READY, and arms a MutationObserver', () => {
    const env = createEnv();
    loadContentScript('content/content.js', env, { chrome: createChrome() });

    const ready = env.posted.mock.calls.filter(
      ([msg]) => msg?.type === '__SECRETS_SPOTTER_READY__',
    );
    expect(ready.length).toBe(1);
    expect(env.mutationObservers.length).toBe(1);
    expect(env.mutationObservers[0].observe).toHaveBeenCalled();
  });

  it('service-worker.js loads with mocked globals and registers an onMessage listener', async () => {
    const { chrome, wasm } = await loadServiceWorker();
    expect(typeof wasm.scan_text).toBe('function');
    expect(chrome.__listeners.onMessage.size).toBeGreaterThan(0);
  });
});
