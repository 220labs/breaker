import test from 'node:test';
import assert from 'node:assert/strict';
import { createPricing } from '../src/pricing.js';
import { createCache } from '../src/cache.js';
import { createStore } from '../src/store.js';
import { similarity } from '../src/embed.js';

const resp = (text) => ({
  id: 'x', object: 'chat.completion', created: 1, model: 'smart',
  choices: [{ index: 0, message: { role: 'assistant', content: text }, finish_reason: 'stop' }],
  usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 },
});
const req = (q, extra = {}) => ({ model: 'smart', messages: [{ role: 'user', content: q }], ...extra });

test('pricing cost math, override and unknown', () => {
  const p = createPricing({ pricing: { 'mock/mock-fast': { input: 1, output: 2 } } });
  assert.equal(p.cost('mock/mock-pro', { prompt_tokens: 1_000_000, completion_tokens: 1_000_000 }), 18);
  assert.equal(p.cost('mock/mock-fast', { prompt_tokens: 1_000_000, completion_tokens: 500_000 }), 2);
  assert.equal(p.cost('nope/none', { prompt_tokens: 100, completion_tokens: 100 }), 0);
});

test('embedding similarity: paraphrase high, unrelated low', () => {
  const s = similarity('What is the capital of France?', "what's the capital city of france");
  assert.ok(s >= 0.8, `paraphrase ${s}`);
  const u = similarity('What is the capital of France?', 'How do I bake sourdough bread at home?');
  assert.ok(u < 0.4, `unrelated ${u}`);
});

test('exact hit returns a copy with fresh id', () => {
  const c = createCache({ cache: { threshold: 0.92 } });
  c.set(req('hello there'), resp('hi'));
  const hit = c.get(req('hello there'));
  assert.equal(hit.kind, 'exact');
  assert.equal(hit.response.choices[0].message.content, 'hi');
  assert.notEqual(hit.response.id, 'x');
  hit.response.choices[0].message.content = 'mutated';
  assert.equal(c.get(req('hello there')).response.choices[0].message.content, 'hi');
});

test('semantic hit on paraphrase, none on unrelated', () => {
  const c = createCache({ cache: { threshold: 0.8 } });
  c.set(req('What is the capital of France?'), resp('Paris'));
  const hit = c.get(req("what's the capital city of france"));
  assert.equal(hit?.kind, 'semantic');
  assert.ok(hit.similarity >= 0.8);
  assert.equal(c.get(req('How do I bake sourdough bread at home?')), null);
  assert.equal(c.get({ ...req("what's the capital city of france"), model: 'other' }), null);
  const s = c.stats();
  assert.equal(s.semanticHits, 1);
  assert.equal(s.size, 1);
  assert.ok(s.misses >= 2);
});

test('no cache at temperature 0.7 or stream', () => {
  const c = createCache({});
  c.set(req('hi', { temperature: 0.7 }), resp('x'));
  assert.equal(c.stats().size, 0);
  assert.equal(c.get(req('hi', { temperature: 0.7 })), null);
  c.set(req('hi', { stream: true }), resp('x'));
  assert.equal(c.stats().size, 0);
});

test('TTL expiry', async () => {
  const c = createCache({ cache: { ttlSeconds: 0.05 } });
  c.set(req('ttl q'), resp('a'));
  assert.ok(c.get(req('ttl q')));
  await new Promise((r) => setTimeout(r, 80));
  assert.equal(c.get(req('ttl q')), null);
  assert.equal(c.stats().size, 0);
});

test('store summary totals, groupings and spendSince', () => {
  const s = createStore(':memory:');
  const now = Date.now();
  const base = { alias: 'fast', model: 'fast', promptTokens: 10, completionTokens: 5, cache: 'miss', attempts: [{ ok: true }], guardrails: [] };
  s.logRequest({ ...base, id: 'a', ts: now - 1000, keyId: 'k1', target: 'mock/mock-fast', status: 200, latencyMs: 100, costUsd: 0.01 });
  s.logRequest({ ...base, id: 'b', ts: now - 500, keyId: 'k1', target: 'mock/mock-fast', status: 502, latencyMs: 300, costUsd: 0, error: 'boom' });
  s.logRequest({ ...base, id: 'c', ts: now - 100, keyId: 'k2', target: 'mock/mock-pro', status: 200, latencyMs: 700, costUsd: 0.03 });
  s.logRequest({ ...base, id: 'd', ts: now - 50, keyId: 'k2', target: null, status: 200, latencyMs: 1, costUsd: 0, cache: 'exact', savedUsd: 0.02 });
  const sum = s.summary();
  assert.equal(sum.totals.requests, 4);
  assert.equal(sum.totals.errors, 1);
  assert.equal(sum.totals.tokens, 60);
  assert.equal(sum.totals.cacheHits, 1);
  assert.ok(Math.abs(sum.totals.costUsd - 0.04) < 1e-9);
  assert.ok(Math.abs(sum.totals.savedUsd - 0.02) < 1e-9);
  const k1 = sum.byKey.find((k) => k.keyId === 'k1');
  assert.deepEqual([k1.requests, k1.errors, k1.tokens], [2, 1, 30]);
  const fast = sum.byTarget.find((t) => t.target === 'mock/mock-fast');
  assert.equal(fast.requests, 2);
  assert.equal(fast.avgLatencyMs, 200);
  assert.ok(sum.perMinute.length >= 1);
  assert.equal(sum.perMinute.reduce((a, m) => a + m.requests, 0), 4);
  assert.ok(Math.abs(s.spendSince('k2', now - 200) - 0.03) < 1e-9);
  assert.equal(s.spendSince('k1', now), 0);
  const rec = s.recent(2);
  assert.equal(rec[0].id, 'd');
  assert.deepEqual(rec[1].attempts, [{ ok: true }]);
});

test('shadow records round trip', () => {
  const s = createStore(':memory:');
  s.logShadow({ id: '1', ts: 1, name: 'x', alias: 'smart', primaryTarget: 'a/b', candidateTarget: 'c/d', score: 0.9, prompt: 'p', primaryText: 'A', candidateText: 'B' });
  s.logShadow({ id: '2', ts: 2, name: 'y', score: 0.1 });
  assert.equal(s.shadowRecords('x').length, 1);
  assert.equal(s.shadowRecords()[0].id, '2');
});
