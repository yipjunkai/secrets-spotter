// service-worker.js is an ESM that reads service-worker globals (`self`,
// `chrome`) and registers listeners at import time. To get a clean instance per
// test we reset the module registry and re-import it — re-importing the wasm
// glue mock in the same pass so the worker and the test share one mock instance.
import { vi } from 'vitest';
import { createChrome } from './chrome.js';

function makeSelf() {
  const listeners = new Map();
  const self = {
    addEventListener: vi.fn((type, fn) => {
      if (!listeners.has(type)) listeners.set(type, new Set());
      listeners.get(type).add(fn);
    }),
  };
  const emit = (type, event = {}) => {
    for (const fn of [...(listeners.get(type) || [])]) fn(event);
  };
  return { self, listeners, emit };
}

/**
 * Fresh service-worker instance with mocked globals.
 * Returns:
 *   chrome      — the chrome mock the worker registered against
 *   wasm        — the wasm glue mock the worker calls (same instance)
 *   self        — { self, emit(type,event) } for error/unhandledrejection
 *   sendMessage — drive the onMessage listener; resolves `done` on sendResponse
 *   commitNav   — fire webNavigation.onCommitted
 */
export async function loadServiceWorker() {
  vi.resetModules();
  const selfMock = makeSelf();
  const chrome = createChrome();
  globalThis.self = selfMock.self;
  globalThis.chrome = chrome;

  const glue = await import('../mocks/wasm-glue.js');
  glue.resetWasm();
  await import('../../background/service-worker.js');

  const sendMessage = (message, sender = {}) => {
    let resolveDone;
    const done = new Promise((r) => (resolveDone = r));
    const sendResponse = vi.fn((res) => resolveDone(res));
    let isAsync = false;
    for (const fn of [...chrome.__listeners.onMessage]) {
      if (fn(message, sender, sendResponse) === true) isAsync = true;
    }
    return { sendResponse, done, isAsync };
  };

  const commitNav = (details) => chrome.__emit('onCommitted', details);

  return { chrome, wasm: glue.wasm, self: selfMock, sendMessage, commitNav };
}

export function teardownServiceWorker() {
  delete globalThis.self;
  delete globalThis.chrome;
}
