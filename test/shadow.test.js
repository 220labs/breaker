import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createShadow } from '../src/shadow.js';

const resp = (text, tokens = 10) => ({
  choices: [{ index: 0, message: { role: 'assistant', content: text }, finish_reason: 'stop' }],
  usage: { prompt_tokens: tokens, completion_tokens: tokens, total_tokens: 2 * tokens },
});
const req = { model: 'smart', messages: [{ role: 'user', content: 'What is the capital of France?' }] };
const primary = { response: resp('Paris'), target: 'mock/pro', latencyMs: 700, alias: 'smart' };
const exp = (o = {}) => ({ name: 'e', alias: 'smart', candidate: 'mock/fast', sampleRate: 1, judge: 'local', ...o });

function setup(experiments, { candidate = () => resp('Paris'), route, similarity } = {}) {
  const records = [];
  const calls = [];
  const router = {
    async callTarget(id, r) { calls.push({ id, r }); return { response: await candidate(r), latencyMs: 100 }; },
    route: route || (async () => { throw new Error('no judge'); }),
  };
  const store = { logShadow: (r) => records.push(r), shadowRecords: () => [...records].reverse() };
  const pricing = { cost: (id, u) => (id === 'mock/pro' ? 0.01 : 0.001) * (u ? 1 : 0) };
  const shadow = createShadow({ shadow: experiments }, router, store, pricing, { similarity: similarity || ((a, b) => (a === b ? 1 : 0)) });
  return { shadow, records, calls };
}

test('mirrors only on matching alias, non-stream, different target', async () => {
  const { shadow, calls } = setup([exp()]);
  shadow.maybeShadow(req, { ...primary, alias: 'other' });
  shadow.maybeShadow({ ...req, stream: true }, primary);
  shadow.maybeShadow(req, { ...primary, target: 'mock/fast' });
  await shadow.flush();
  assert.equal(calls.length, 0);
  shadow.maybeShadow(req, primary);
  await shadow.flush();
  assert.equal(calls.length, 1);
  assert.equal(calls[0].id, 'mock/fast');
  assert.equal(calls[0].r.stream, false);
});

test('sampleRate 0 never mirrors', async () => {
  const { shadow, calls } = setup([exp({ sampleRate: 0 })]);
  for (let i = 0; i < 20; i++) shadow.maybeShadow(req, primary);
  await shadow.flush();
  assert.equal(calls.length, 0);
});

test('candidate throwing records candidateError and never throws', async () => {
  const { shadow, records } = setup([exp()], { candidate: () => { throw new Error('boom'); } });
  assert.doesNotThrow(() => shadow.maybeShadow(req, primary));
  await shadow.flush();
  assert.equal(records.length, 1);
  assert.equal(records[0].candidateError, 'boom');
  assert.equal(records[0].score, null);
  assert.equal(shadow.report()[0].candidateErrors, 1);
  assert.equal(shadow.report()[0].samples, 0);
});

test("verdict 'collecting' then 'switch' after 5 agreeing cheaper samples", async () => {
  const { shadow } = setup([exp()]);
  for (let i = 0; i < 4; i++) { shadow.maybeShadow(req, primary); await shadow.flush(); }
  assert.equal(shadow.report()[0].verdict, 'collecting');
  shadow.maybeShadow(req, primary);
  await shadow.flush();
  const r = shadow.report()[0];
  assert.equal(r.samples, 5);
  assert.equal(r.verdict, 'switch');
  assert.equal(r.agreement, 1);
  assert.equal(r.projectedSavingsPct, 90);
  assert.equal(r.candidateP50Ms, 100);
});

test("verdict 'keep' when disagreeing", async () => {
  const { shadow } = setup([exp()], { candidate: () => resp('Lyon') });
  for (let i = 0; i < 6; i++) { shadow.maybeShadow(req, primary); await shadow.flush(); }
  const r = shadow.report()[0];
  assert.equal(r.verdict, 'keep');
  assert.equal(r.agreeRate, 0);
  assert.equal(r.examples.length, 3);
});

test('model judge parses integer; falls back to local on garbage and failure', async () => {
  const judged = setup([exp({ judge: 'fast' })], { route: async () => ({ response: resp('Score: 8') }), similarity: () => 0.123 });
  judged.shadow.maybeShadow(req, primary);
  await judged.shadow.flush();
  assert.equal(judged.records[0].score, 0.8);

  const garbage = setup([exp({ judge: 'fast' })], { route: async () => ({ response: resp('no idea') }), similarity: () => 0.5 });
  garbage.shadow.maybeShadow(req, primary);
  await garbage.shadow.flush();
  assert.equal(garbage.records[0].score, 0.5);

  const failing = setup([exp({ judge: 'fast' })], { route: async () => { throw new Error('down'); }, similarity: () => 0.4 });
  failing.shadow.maybeShadow(req, primary);
  await failing.shadow.flush();
  assert.equal(failing.records[0].score, 0.4);
});

test('caps in-flight shadow calls at 4', async () => {
  let release;
  const gate = new Promise((r) => { release = r; });
  const { shadow, calls } = setup([exp()], { candidate: async () => { await gate; return resp('Paris'); } });
  for (let i = 0; i < 10; i++) shadow.maybeShadow(req, primary);
  assert.equal(shadow.pending(), 4);
  release();
  await shadow.flush();
  assert.equal(calls.length, 4);
  assert.equal(shadow.pending(), 0);
});
