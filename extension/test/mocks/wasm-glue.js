// Controllable stand-in for the wasm-pack glue
// (extension/wasm/secrets_spotter_wasm.js), which is a gitignored build
// artifact. vitest.config.js aliases the worker's import here.
//
// Tests import `wasm` to set return values / assert calls; service-worker.js
// imports the default (init) + named exports below, which delegate to it.
import { vi } from 'vitest';

export const wasm = {
  init: vi.fn(async () => {}),
  scan_text: vi.fn(() => []),
  pattern_count: vi.fn(() => 42),
  should_scan: vi.fn(() => true),
  parse_cookies: vi.fn((raw) => raw),
  format_attributes: vi.fn((json) => json),
  merge_findings: vi.fn((existing, incoming) => [...existing, ...incoming]),
};

const DEFAULTS = {
  init: async () => {},
  scan_text: () => [],
  pattern_count: () => 42,
  should_scan: () => true,
  parse_cookies: (raw) => raw,
  format_attributes: (json) => json,
  merge_findings: (existing, incoming) => [...existing, ...incoming],
};

/** Reset every wasm fn to its default behavior and clear call history. */
export function resetWasm() {
  for (const [name, impl] of Object.entries(DEFAULTS)) {
    wasm[name].mockReset();
    wasm[name].mockImplementation(impl);
  }
}

export default (...args) => wasm.init(...args);
export const scan_text = (...a) => wasm.scan_text(...a);
export const pattern_count = (...a) => wasm.pattern_count(...a);
export const should_scan = (...a) => wasm.should_scan(...a);
export const parse_cookies = (...a) => wasm.parse_cookies(...a);
export const format_attributes = (...a) => wasm.format_attributes(...a);
export const merge_findings = (...a) => wasm.merge_findings(...a);
