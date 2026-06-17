// Service worker: badge accounting, source normalization, the SCAN_TEXT
// pipeline (filter → preprocess → scan → merge → badge), DOM-finding clearing,
// and navigation reset. The wasm glue and chrome.* are mocked.
import { afterEach, describe, it, expect, vi } from 'vitest';
import {
  loadServiceWorker,
  teardownServiceWorker,
} from './helpers/loadServiceWorker.js';

afterEach(teardownServiceWorker);

const finding = (severity, fullMatch) => ({
  kind: 'GenericApiKey',
  label: 'x',
  matched_text: 'redacted',
  full_match: fullMatch,
  start: 0,
  end: 10,
  severity,
});

const scanMsg = (over = {}) => ({
  type: 'SCAN_TEXT',
  text: 'some page text here',
  url: 'https://app.example.test/page',
  source: 'dom',
  ...over,
});

describe('service worker — badge', () => {
  it('counts only Critical/High findings on the badge', async () => {
    const { sendMessage, chrome, wasm } = await loadServiceWorker();
    wasm.scan_text.mockReturnValue([
      finding('Critical', 'a'),
      finding('High', 'b'),
      finding('Medium', 'c'),
      finding('Low', 'd'),
    ]);

    await sendMessage(scanMsg(), { tab: { id: 7 } }).done;

    const texts = chrome.action.setBadgeText.mock.calls.map(([a]) => a.text);
    expect(texts).toContain('2'); // Critical + High only
  });

  it('does not show a count when only low-severity findings exist', async () => {
    const { sendMessage, chrome, wasm } = await loadServiceWorker();
    wasm.scan_text.mockReturnValue([finding('Medium', 'a'), finding('Low', 'b')]);

    await sendMessage(scanMsg(), { tab: { id: 7 } }).done;

    const texts = chrome.action.setBadgeText.mock.calls.map(([a]) => a.text);
    expect(texts).not.toContain('1');
    expect(texts).not.toContain('2');
  });
});

describe('service worker — SCAN_TEXT pipeline', () => {
  it('skips URLs that should_scan rejects (no scan, skipped tally bumped)', async () => {
    const { sendMessage, wasm } = await loadServiceWorker();
    wasm.should_scan.mockReturnValue(false);

    const { done } = sendMessage(
      scanMsg({ url: 'https://app.example.test/logo.png', source: 'network:fetch' }),
      { tab: { id: 3 } },
    );
    const res = await done;

    expect(res).toEqual({ findings: [] });
    expect(wasm.scan_text).not.toHaveBeenCalled();

    const got = await sendMessage({ type: 'GET_FINDINGS', tabId: 3 }).done;
    expect(got.skippedCount).toBe(1);
  });

  it('preprocesses cookies and structured DOM through the wasm helpers', async () => {
    const { sendMessage, wasm } = await loadServiceWorker();

    await sendMessage(
      scanMsg({ text: 'sid=abcdefghij; theme=dark', source: 'cookie' }),
      { tab: { id: 1 } },
    ).done;
    expect(wasm.parse_cookies).toHaveBeenCalledWith('sid=abcdefghij; theme=dark');

    await sendMessage(
      scanMsg({ text: '[{"name":"data-x","value":"hello-world"}]', source: 'dom:structured' }),
      { tab: { id: 1 } },
    ).done;
    expect(wasm.format_attributes).toHaveBeenCalled();
  });

  it('normalizes network/header sources in the per-tab tally', async () => {
    const { sendMessage } = await loadServiceWorker();

    await sendMessage(
      scanMsg({ text: 'xxxxxxxxxx', url: 'https://app.example.test/a', source: 'network:header:fetch' }),
      { tab: { id: 9 } },
    ).done;

    const got = await sendMessage({ type: 'GET_FINDINGS', tabId: 9 }).done;
    expect(got.sources).toMatchObject({ fetch: 1 });
  });
});

describe('service worker — finding lifecycle', () => {
  it('CLEAR_DOM_FINDINGS drops DOM findings but keeps network ones', async () => {
    const { sendMessage, wasm } = await loadServiceWorker();

    wasm.scan_text.mockReturnValueOnce([finding('High', 'dom-1')]);
    await sendMessage(scanMsg({ source: 'dom' }), { tab: { id: 5 } }).done;

    wasm.scan_text.mockReturnValueOnce([finding('High', 'net-1')]);
    await sendMessage(scanMsg({ source: 'network:fetch' }), { tab: { id: 5 } }).done;

    sendMessage({ type: 'CLEAR_DOM_FINDINGS' }, { tab: { id: 5 } });
    await new Promise((r) => setTimeout(r));

    const got = await sendMessage({ type: 'GET_FINDINGS', tabId: 5 }).done;
    const matches = got.findings.map((f) => f.full_match);
    expect(matches).toEqual(['net-1']);
  });

  it('webNavigation onCommitted resets the tab and shows the loading badge', async () => {
    const { sendMessage, commitNav, chrome, wasm } = await loadServiceWorker();

    wasm.scan_text.mockReturnValueOnce([finding('Critical', 'old')]);
    await sendMessage(scanMsg(), { tab: { id: 4 } }).done;

    commitNav({ frameId: 0, tabId: 4, documentId: 'doc-new' });
    await new Promise((r) => setTimeout(r));

    const texts = chrome.action.setBadgeText.mock.calls.map(([a]) => a.text);
    expect(texts).toContain('...'); // loading badge

    const got = await sendMessage({ type: 'GET_FINDINGS', tabId: 4 }).done;
    expect(got.findings).toEqual([]);
  });

  it('ignores sub-frame navigations', async () => {
    const { commitNav, chrome } = await loadServiceWorker();
    commitNav({ frameId: 1, tabId: 4, documentId: 'doc-sub' });
    await new Promise((r) => setTimeout(r));
    expect(chrome.action.setBadgeText).not.toHaveBeenCalled();
  });
});

const drain = async (n = 40) => {
  for (let i = 0; i < n; i += 1) await new Promise((r) => setTimeout(r, 0));
};

describe('service worker — log + response hygiene', () => {
  it('serializes concurrent error-log writes without losing entries', async () => {
    const { sendMessage } = await loadServiceWorker();
    // Fire many LOG_ERROR messages concurrently (no await between) — the old
    // get/modify/set would clobber all but the last.
    for (let i = 0; i < 8; i += 1) {
      sendMessage({ type: 'LOG_ERROR', src: 'content', msg: `err-${i}`, url: 'https://x.test/' });
    }
    await drain();
    const res = await sendMessage({ type: 'GET_ERROR_LOG' }).done;
    expect(res.errorLog).toHaveLength(8);
  });

  it('strips query strings and fragments from logged URLs', async () => {
    const { sendMessage } = await loadServiceWorker();
    sendMessage({
      type: 'LOG_ERROR',
      src: 'content',
      msg: 'boom',
      url: 'https://x.test/path/a?token=shouldnotpersist&u=1#frag',
    });
    await drain(20);
    const res = await sendMessage({ type: 'GET_ERROR_LOG' }).done;
    expect(res.errorLog[0].url).toBe('https://x.test/path/a');
  });

  it('does not echo findings in the SCAN_TEXT response', async () => {
    const { sendMessage, wasm } = await loadServiceWorker();
    wasm.scan_text.mockReturnValue([finding('High', 'x')]);
    const res = await sendMessage(scanMsg(), { tab: { id: 1 } }).done;
    expect(res).toEqual({ ok: true });
  });
});

describe('service worker — SCAN_EXTERNAL (bundle fetch)', () => {
  const REAL_FETCH = globalThis.fetch;
  afterEach(() => { globalThis.fetch = REAL_FETCH; });

  const okJs = (body) => ({
    ok: true,
    headers: { get: () => 'application/javascript' },
    text: async () => body,
    body: null, // exercises the text() path in fetchCapped
  });

  it('fetches external scripts and merges findings tagged source=script', async () => {
    const { sendMessage, wasm } = await loadServiceWorker();
    globalThis.fetch = vi.fn(async () => okJs('var k = "leaked-bundle-secret";'));
    wasm.scan_text.mockReturnValue([finding('Critical', 'leaked-bundle-secret')]);

    await sendMessage(
      {
        type: 'SCAN_EXTERNAL',
        urls: ['https://app.example.test/app.js'],
        url: 'https://app.example.test/page',
      },
      { tab: { id: 11 }, documentId: 'doc-1' },
    ).done;

    expect(globalThis.fetch).toHaveBeenCalledTimes(1);
    const got = await sendMessage({ type: 'GET_FINDINGS', tabId: 11 }).done;
    expect(got.findings.map((f) => f.full_match)).toContain('leaked-bundle-secret');
    expect(got.findings[0].source).toBe('script');
    expect(got.sources).toMatchObject({ script: 1 });
  });

  it('skips URLs that should_scan rejects, without fetching', async () => {
    const { sendMessage, wasm } = await loadServiceWorker();
    globalThis.fetch = vi.fn();
    wasm.should_scan.mockReturnValue(false);

    await sendMessage(
      {
        type: 'SCAN_EXTERNAL',
        urls: ['https://cdnjs.cloudflare.com/x.js'],
        url: 'https://app.example.test/page',
      },
      { tab: { id: 12 } },
    ).done;

    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it('fetches each unique URL only once across requests (dedup cache)', async () => {
    const { sendMessage, wasm } = await loadServiceWorker();
    globalThis.fetch = vi.fn(async () => okJs('noop();'));
    wasm.scan_text.mockReturnValue([]);
    const url = 'https://app.example.test/cached.js';

    await sendMessage({ type: 'SCAN_EXTERNAL', urls: [url], url: 'p' }, { tab: { id: 13 } }).done;
    await sendMessage({ type: 'SCAN_EXTERNAL', urls: [url], url: 'p' }, { tab: { id: 13 } }).done;

    expect(globalThis.fetch).toHaveBeenCalledTimes(1);
  });
});
