import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';

export default defineConfig({
  test: {
    // The content scripts are loaded as text into per-test happy-dom `Window`
    // instances (see extension/test/helpers/loadScript.js), and the service
    // worker is a plain ESM imported directly — so we don't need a global DOM.
    environment: 'node',
    include: ['extension/test/**/*.test.js'],
    globals: false,
  },
  resolve: {
    alias: [
      // service-worker.js imports the wasm-pack glue, which is a gitignored
      // build artifact (extension/wasm/* — absent in CI). Redirect that import
      // to a controllable mock so the worker can be unit-tested without a build.
      // NB: a regex alias does a partial `.replace()`, so the pattern must match
      // the *whole* specifier — otherwise only the tail is swapped, mangling the
      // `../` prefix into a broken path.
      {
        find: /^.*\/secrets_spotter_wasm\.js$/,
        replacement: fileURLToPath(
          new URL('./extension/test/mocks/wasm-glue.js', import.meta.url),
        ),
      },
    ],
  },
});
