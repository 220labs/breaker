import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { createProviders, setChaos, getChaos } from '../src/providers/index.js';
import { createRouter } from '../src/router.js';

const config = {
  providers: { mock: {}, openai: { apiKeyEnv: 'GW_TEST_NO_SUCH_KEY' } },
  models: {
    smart: { strategy: 'priority', targets: ['mock/mock-flaky', 'mock/mock-fast'], fallback: ['alt'] },
    fast: { strategy: 'priority', targets: ['mock/mock-fast', 'mock/mock-alt'] },
    alt: { strategy: 'priority', targets: ['mock/mock-alt'] },
    rr: { strategy: 'round-robin', targets: ['mock/mock-fast', 'mock/mock-alt'] },
    unavailable: { strategy: 'priority', targets: ['openai/gpt-4o', 'mock/mock-fast'] },
    loop: { strategy: 'priority', targets: ['mock/mock-flaky'], fallback: ['loop2'] },
    loop2: { strategy: 'priority', targets: ['mock/mock-flaky'], fallback: ['loop'] },
  },
};
const req = (model, extra = {}) => ({ model, messages: [{ role: 'user', content: 'What is a circuit breaker?' }], ...extra });

beforeEach(() => {
  for (const m of Object.keys(getChaos())) setChaos(m, { failRate: m === 'mock-flaky' ? 1 : 0, latencyMs: 1 });
});

const make = () => createRouter(config, createProviders(config));

test('failover from mock-flaky to mock-fast', async () => {
  const r = make();
  const out = await r.route(req('smart'));
  assert.equal(out.target.id, 'mock/mock-fast');
  assert.equal(out.attempts.length, 2);
  assert.equal(out.attempts[0].ok, false);
  assert.equal(out.attempts[0].status, 502);
  assert.equal(out.attempts[1].ok, true);
  assert.equal(out.response.choices[0].message.role, 'assistant');
  assert.equal(out.response.model, 'mock-fast');
});

test('circuit opens after 3 consecutive failures and skips the target', async () => {
  const r = make();
  for (let i = 0; i < 3; i++) await r.route(req('smart'));
  const h = Object.fromEntries(r.health().map((x) => [x.id, x]));
  assert.equal(h['mock/mock-flaky'].state, 'open');
  assert.equal(h['mock/mock-flaky'].failures, 3);
  const out = await r.route(req('smart'));
  assert.equal(out.attempts.length, 1); // flaky skipped, no attempt made
  assert.equal(out.target.id, 'mock/mock-fast');
});

test('priority order and skipping unavailable providers', async () => {
  const r = make();
  assert.deepEqual(r.resolve('fast').targets.map((t) => t.id), ['mock/mock-fast', 'mock/mock-alt']);
  const out = await r.route(req('unavailable'));
  assert.equal(out.target.id, 'mock/mock-fast');
  assert.equal(out.attempts.length, 1);
});

test('round-robin rotates; direct provider/model names work', async () => {
  const r = make();
  assert.equal(r.resolve('rr').targets[0].id, 'mock/mock-fast');
  assert.equal(r.resolve('rr').targets[0].id, 'mock/mock-alt');
  const d = r.resolve('mock/mock-pro');
  assert.equal(d.alias, null);
  assert.deepEqual(d.targets.map((t) => t.model), ['mock-pro']);
});

test('unknown model is a 404 model_not_found', async () => {
  const r = make();
  assert.throws(() => r.resolve('nope'), (e) => e.status === 404 && e.code === 'model_not_found');
  await assert.rejects(r.route(req('nope')), (e) => e.status === 404);
});

test('fallback aliases are tried after targets; loops terminate', async () => {
  setChaos('mock-fast', { failRate: 1 });
  const r = make();
  const out = await r.route(req('smart'));
  assert.equal(out.target.id, 'mock/mock-alt');
  assert.deepEqual(out.attempts.map((a) => a.target), ['mock/mock-flaky', 'mock/mock-fast', 'mock/mock-alt']);
  await assert.rejects(r.route(req('loop')), (e) => e.code === 'all_targets_failed' && e.attempts.length === 1);
});

test('streaming yields chunks then usage, with failover before the first chunk', async () => {
  const r = make();
  const { target, stream, attempts } = await r.routeStream(req('smart', { stream: true }));
  assert.equal(target.id, 'mock/mock-fast');
  assert.equal(attempts.length, 2);
  const chunks = [];
  for await (const c of stream) chunks.push(c);
  assert.ok(chunks.length > 3);
  assert.equal(chunks.at(-1).object, 'chat.completion.chunk');
  assert.ok(chunks.at(-1).usage.total_tokens > 0);
  const text = chunks.map((c) => c.choices[0]?.delta?.content ?? '').join('');
  assert.match(text, /circuit breaker/);
});

test('callTarget calls directly without failover; judge prompt gets a number', async () => {
  const r = make();
  const { response, latencyMs } = await r.callTarget('mock/mock-pro', req('x', { messages: [{ role: 'user', content: 'Please score 0-10 how equivalent these are' }] }));
  assert.match(response.choices[0].message.content, /^\d+$/);
  assert.ok(latencyMs >= 0);
  await assert.rejects(r.callTarget('mock/mock-flaky', req('x')), (e) => e.status === 502 && e.extra.retryable === true);
});

test('messagesUpstream passes client auth through only without a configured key', async () => {
  const { messagesUpstream } = await import('../src/providers/anthropic.js');
  const realFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, init) => { calls.push({ url, init }); return new Response('{"err":1}', { status: 400 }); };
  const saved = process.env.GW_TEST_ANTHROPIC;
  try {
    delete process.env.GW_TEST_ANTHROPIC;
    const client = { authorization: 'Bearer oauth-x', 'x-api-key': 'client-key', 'anthropic-beta': 'b1', cookie: 'nope' };
    const res = await messagesUpstream({ model: 'm', messages: [] }, client, { apiKeyEnv: 'GW_TEST_ANTHROPIC' });
    assert.equal(res.status, 400); // returned, not thrown
    assert.equal(calls[0].url, 'https://api.anthropic.com/v1/messages');
    const h = calls[0].init.headers;
    assert.equal(h.authorization, 'Bearer oauth-x');
    assert.equal(h['x-api-key'], 'client-key');
    assert.equal(h['anthropic-beta'], 'b1');
    assert.equal(h['anthropic-version'], '2023-06-01');
    assert.equal(h.cookie, undefined);
    process.env.GW_TEST_ANTHROPIC = 'own-key';
    await messagesUpstream({}, client, { apiKeyEnv: 'GW_TEST_ANTHROPIC' });
    const h2 = calls[1].init.headers;
    assert.equal(h2['x-api-key'], 'own-key');
    assert.equal(h2.authorization, undefined);
    globalThis.fetch = async () => { throw new TypeError('fetch failed'); };
    await assert.rejects(messagesUpstream({}, {}, {}), (e) => e.status === 502 && e.code === 'upstream_unreachable' && e.extra.retryable === true);
  } finally {
    globalThis.fetch = realFetch;
    if (saved === undefined) delete process.env.GW_TEST_ANTHROPIC; else process.env.GW_TEST_ANTHROPIC = saved;
  }
});
