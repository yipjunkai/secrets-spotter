// interceptor.js (MAIN world): patches fetch/XHR/WebSocket/SSE, buffers captured
// payloads until the ISOLATED-world relay announces readiness, and emits SPA
// navigation signals. It posts everything via window.postMessage (spied as
// env.posted); it never touches chrome.*.
import { afterEach, describe, it, expect, vi } from 'vitest';
import { createChrome } from './helpers/chrome.js';
import {
  createEnv,
  loadContentScript,
  makeResponse,
  makeStreamResponse,
} from './helpers/loadScript.js';

const ORIGIN = 'https://app.example.test';
const flush = async (n = 4) => {
  for (let i = 0; i < n; i += 1) await new Promise((r) => setTimeout(r, 0));
};

const load = (env) =>
  loadContentScript('content/interceptor.js', env, { chrome: createChrome() });

const intercepts = (env) =>
  env.posted.mock.calls
    .map(([m]) => m)
    .filter((m) => m?.type === '__SECRETS_SPOTTER_INTERCEPT__');

const ready = (env) =>
  env.emit('message', {
    source: env.window,
    origin: ORIGIN,
    data: { type: '__SECRETS_SPOTTER_READY__' },
  });

afterEach(() => vi.useRealTimers());

describe('interceptor.js — relay buffering', () => {
  it('buffers captured payloads until READY, then flushes them', async () => {
    const env = createEnv({ url: `${ORIGIN}/page` });
    load(env);

    await env.window.fetch(`${ORIGIN}/api`, {
      method: 'POST',
      body: 'request-body-payload',
      headers: { 'x-test': 'header-value-here' },
    });
    await flush();

    // Relay not ready yet — nothing posted to the page.
    expect(intercepts(env)).toHaveLength(0);

    ready(env);

    const texts = intercepts(env).map((m) => m.text);
    expect(texts).toContain('request-body-payload');
  });
});

describe('interceptor.js — response skip filter', () => {
  it('relays a scannable JSON response body', async () => {
    const env = createEnv({ url: `${ORIGIN}/page` });
    load(env);
    ready(env); // post directly from here on

    env.fetchMock.mockResolvedValueOnce(
      makeResponse('response-json-body-text', {
        headers: { 'content-type': 'application/json' },
      }),
    );
    await env.window.fetch(`${ORIGIN}/api/data`);
    await flush();

    const texts = intercepts(env).map((m) => m.text);
    expect(texts).toContain('response-json-body-text');
  });

  it('does not relay a skipped (image) response body', async () => {
    const env = createEnv({ url: `${ORIGIN}/page` });
    load(env);
    ready(env);

    env.fetchMock.mockResolvedValueOnce(
      makeResponse('binary-image-bytes-here', {
        headers: { 'content-type': 'image/png' },
      }),
    );
    await env.window.fetch(`${ORIGIN}/logo.png`);
    await flush();

    expect(intercepts(env)).toHaveLength(0);
  });
});

describe('interceptor.js — navigation (nav-race)', () => {
  it('emits a NAVIGATION signal on history.pushState to a new URL', () => {
    const env = createEnv({ url: `${ORIGIN}/page` });
    load(env);

    env.window.history.pushState({}, '', `${ORIGIN}/new-route`);

    const nav = env.posted.mock.calls
      .map(([m]) => m)
      .find((m) => m?.type === '__SECRETS_SPOTTER_NAVIGATION__');
    expect(nav).toBeTruthy();
    expect(nav.url).toContain('/new-route');
  });
});

describe('interceptor.js — capture filter parity with core', () => {
  it('relays source-map response bodies (regression: .map was skipped)', async () => {
    const env = createEnv({ url: `${ORIGIN}/page` });
    load(env);
    ready(env);

    env.fetchMock.mockResolvedValueOnce(
      makeResponse('sourcemap-sourcesContent-payload', {
        headers: { 'content-type': 'application/json' },
      }),
    );
    await env.window.fetch(`${ORIGIN}/static/bundle.js.map`);
    await flush();

    const texts = intercepts(env).map((m) => m.text);
    expect(texts).toContain('sourcemap-sourcesContent-payload');
  });

  it('relays first-party /cdn path responses (regression: bare cdn was skipped)', async () => {
    const env = createEnv({ url: `${ORIGIN}/page` });
    load(env);
    ready(env);

    env.fetchMock.mockResolvedValueOnce(
      makeResponse('first-party-cdn-config-payload', {
        headers: { 'content-type': 'application/json' },
      }),
    );
    await env.window.fetch(`${ORIGIN}/cdn/user-config.json`);
    await flush();

    const texts = intercepts(env).map((m) => m.text);
    expect(texts).toContain('first-party-cdn-config-payload');
  });

  it('still skips known CDN hosts', async () => {
    const env = createEnv({ url: `${ORIGIN}/page` });
    load(env);
    ready(env);

    env.fetchMock.mockResolvedValueOnce(makeResponse('cdn-library-source'));
    await env.window.fetch('https://cdn.jsdelivr.net/npm/chart.js');
    await flush();

    expect(intercepts(env)).toHaveLength(0);
  });
});

describe('interceptor.js — Request-object inputs', () => {
  it('captures headers and body of a Request-object fetch input', async () => {
    const env = createEnv({ url: `${ORIGIN}/page` });
    load(env);
    ready(env);

    const request = new Request(`${ORIGIN}/api/send`, {
      method: 'POST',
      headers: { 'x-api-key': 'header-credential-value-123' },
      body: 'request-object-body-payload',
      duplex: 'half', // Node's fetch requires it for bodied requests
    });
    await env.window.fetch(request);
    await flush();

    const texts = intercepts(env).map((m) => m.text);
    expect(texts.some((t) => t.includes('x-api-key: header-credential-value-123'))).toBe(true);
    expect(texts).toContain('request-object-body-payload');
  });

  it('the original Request body still reaches fetch (clone, not consume)', async () => {
    const env = createEnv({ url: `${ORIGIN}/page` });
    load(env);
    ready(env);

    const request = new Request(`${ORIGIN}/api/send`, {
      method: 'POST',
      body: 'must-survive-interception',
      duplex: 'half',
    });
    await env.window.fetch(request);
    await flush();

    const passed = env.fetchMock.mock.calls[0][0];
    expect(passed.bodyUsed).toBe(false);
    await expect(passed.text()).resolves.toBe('must-survive-interception');
  });
});

describe('interceptor.js — request-phase skip filter', () => {
  it('does not relay request headers/body for skipped URLs (fetch)', async () => {
    const env = createEnv({ url: `${ORIGIN}/page` });
    load(env);
    ready(env);

    env.fetchMock.mockResolvedValueOnce(
      makeResponse('png-bytes', { headers: { 'content-type': 'image/png' } }),
    );
    await env.window.fetch(`${ORIGIN}/upload/logo.png`, {
      method: 'POST',
      headers: { authorization: 'Bearer header-on-skipped-url' },
      body: 'body-on-skipped-url-12345',
    });
    await flush();

    expect(intercepts(env)).toHaveLength(0);
  });
});

describe('interceptor.js — response streaming cap', () => {
  it('streams and relays a normal-size response body', async () => {
    const env = createEnv({ url: `${ORIGIN}/page` });
    load(env);
    ready(env);

    env.fetchMock.mockResolvedValueOnce(
      makeResponse('streamed-response-body-text', {
        headers: { 'content-type': 'application/json' },
      }),
    );
    await env.window.fetch(`${ORIGIN}/api/data`);
    await flush();

    expect(intercepts(env).map((m) => m.text)).toContain('streamed-response-body-text');
  });

  it('caps an oversized body at 2MB and stops reading early', async () => {
    const env = createEnv({ url: `${ORIGIN}/page` });
    load(env);
    ready(env);

    const big = 'x'.repeat(3_000_000);
    const { response, stats } = makeStreamResponse(big, {
      headers: { 'content-type': 'application/json' },
    });
    env.fetchMock.mockResolvedValueOnce(response);
    await env.window.fetch(`${ORIGIN}/api/big`);
    await flush(10);

    const relayed = intercepts(env)
      .map((m) => m.text)
      .find((t) => t.startsWith('xxx'));
    expect(relayed).toBeDefined();
    expect(relayed.length).toBe(2_000_000); // capped at MAX_SIZE
    expect(stats.bytesPulled).toBeLessThan(2_200_000); // didn't drain the full 3MB
    expect(stats.cancelled).toBe(true); // reader was cancelled
  });
});

describe('interceptor.js — websocket batching', () => {
  it('batches WebSocket messages and relays them after the flush interval', async () => {
    vi.useFakeTimers();
    const env = createEnv({ url: `${ORIGIN}/page` });
    load(env);
    ready(env);

    // eslint-disable-next-line no-new
    new env.window.WebSocket(`wss://${'app.example.test'}/sock`);
    const socket = env.WebSocket.instances[0];
    socket.dispatch('message', { data: 'ws-message-payload-text' });

    // Still buffering inside the batch window.
    expect(intercepts(env)).toHaveLength(0);

    await vi.advanceTimersByTimeAsync(2000);

    const texts = intercepts(env).map((m) => m.text);
    expect(texts.some((t) => t.includes('ws-message-payload-text'))).toBe(true);
  });
});
