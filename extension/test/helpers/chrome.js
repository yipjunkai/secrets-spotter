// A minimal mock of the `chrome.*` surface the extension touches. Storage areas
// are backed by in-memory maps; events record their listeners so tests can fire
// them via `chrome.__emit(name, ...args)`. Everything is a `vi.fn` so calls can
// be asserted and behavior overridden per test.
import { vi } from 'vitest';

function makeStorageArea(store) {
  return {
    get: vi.fn(async (keys) => {
      if (keys == null) return Object.fromEntries(store);
      if (typeof keys === 'string') {
        return store.has(keys) ? { [keys]: store.get(keys) } : {};
      }
      if (Array.isArray(keys)) {
        const out = {};
        for (const k of keys) if (store.has(k)) out[k] = store.get(k);
        return out;
      }
      // Object form: keys map to defaults, overridden by stored values.
      const out = { ...keys };
      for (const k of Object.keys(keys)) if (store.has(k)) out[k] = store.get(k);
      return out;
    }),
    set: vi.fn(async (obj) => {
      for (const [k, v] of Object.entries(obj)) store.set(k, v);
    }),
    remove: vi.fn(async (key) => {
      for (const k of Array.isArray(key) ? key : [key]) store.delete(k);
    }),
  };
}

export function createChrome() {
  const stores = { local: new Map(), session: new Map() };
  const listeners = {};
  const makeEvent = (name) => {
    const set = new Set();
    listeners[name] = set;
    return {
      addListener: vi.fn((fn) => set.add(fn)),
      removeListener: vi.fn((fn) => set.delete(fn)),
      hasListener: vi.fn((fn) => set.has(fn)),
    };
  };

  const chrome = {
    runtime: {
      id: 'test-extension-id',
      lastError: null,
      getURL: vi.fn((p) => `chrome-extension://test/${p}`),
      sendMessage: vi.fn(),
      onMessage: makeEvent('onMessage'),
      onInstalled: makeEvent('onInstalled'),
    },
    storage: {
      local: makeStorageArea(stores.local),
      session: { ...makeStorageArea(stores.session), setAccessLevel: vi.fn() },
    },
    action: {
      setBadgeText: vi.fn(async () => {}),
      setBadgeBackgroundColor: vi.fn(async () => {}),
    },
    webNavigation: { onCommitted: makeEvent('onCommitted') },
    tabs: { onRemoved: makeEvent('onRemoved') },

    // Test affordances (double-underscore so they can't collide with the API).
    __stores: stores,
    __listeners: listeners,
    /** Invoke every listener registered on a chrome event. */
    __emit(name, ...args) {
      for (const fn of [...(listeners[name] || [])]) fn(...args);
    },
  };
  return chrome;
}
