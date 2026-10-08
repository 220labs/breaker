// Mock provider: lets the whole demo run with no API keys. Answers are deterministic
// (derived from the last user message) but worded differently per model, so shadow
// evaluation has something real to judge. Chaos settings are the only module-level state.
import { randomUUID } from 'node:crypto';
import { GatewayError } from '../errors.js';
import { estimateTokens, messageText, estimateRequestTokens } from '../tokens.js';

const MODELS = {
  'mock-fast': { latencyMs: 150, failRate: 0 },
  'mock-pro': { latencyMs: 700, failRate: 0 },
  'mock-alt': { latencyMs: 300, failRate: 0 },
  'mock-flaky': { latencyMs: 200, failRate: 0.5 },
};

const chaos = new Map(); // model -> {failRate?, latencyMs?}

export function setChaos(model, { failRate, latencyMs } = {}) {
  const cur = chaos.get(model) ?? {};
  if (failRate !== undefined) cur.failRate = Number(failRate);
  if (latencyMs !== undefined) cur.latencyMs = Number(latencyMs);
  chaos.set(model, cur);
}

export function getChaos() {
  const out = {};
  for (const [model, base] of Object.entries(MODELS)) out[model] = { ...base, ...(chaos.get(model) ?? {}) };
  for (const [model, c] of chaos) if (!out[model]) out[model] = { ...c };
  return out;
}

function settings(model) {
  return { ...(MODELS[model] ?? { latencyMs: 300, failRate: 0 }), ...(chaos.get(model) ?? {}) };
}

const sleep = (ms, signal) =>
  new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(abortError(signal));
    const t = setTimeout(() => { signal?.removeEventListener('abort', onAbort); resolve(); }, ms);
    const onAbort = () => { clearTimeout(t); reject(abortError(signal)); };
    signal?.addEventListener('abort', onAbort, { once: true });
  });

function abortError(signal) {
  const timedOut = signal?.reason?.name === 'TimeoutError';
  return timedOut
    ? new GatewayError(504, 'upstream_timeout', 'mock upstream timed out', { retryable: true })
    : new GatewayError(499, 'client_closed', 'request aborted', { retryable: false });
}

function hash(s) {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
  return h >>> 0;
}

function lastUser(req) {
  const msgs = req.messages ?? [];
  for (let i = msgs.length - 1; i >= 0; i--) if (msgs[i].role === 'user') return messageText(msgs[i].content);
  return messageText(msgs.at(-1)?.content);
}

function topic(text) {
  return text.replace(/\s+/g, ' ').trim().split(' ').slice(0, 14).join(' ').replace(/[.?!]+$/, '');
}

export function mockAnswer(req, model) {
  const all = (req.messages ?? []).map((m) => messageText(m.content)).join('\n');
  const user = lastUser(req);
  // A judge prompt (shadow evaluation) wants a number, not prose.
  if (/score\s*(0\s*[-–to]+\s*10|from 0 to 10)/i.test(all)) {
    return model === 'mock-pro' ? String(7 + (hash(user) % 3)) : '7';
  }
  const t = topic(user) || 'your question';
  const h = hash(t);
  switch (model) {
    case 'mock-pro':
      return `Here is a fuller answer about ${t}. The key point is that ${t} depends on context, and the most reliable approach is to state your assumptions, check them against real data, and keep the solution simple. In practice, start with the common case, measure the result, and refine only where the numbers justify it. Variant ${h % 97}.`;
    case 'mock-alt':
      return `On ${t}: the practical approach is to keep the solution simple, check assumptions against real data, and refine where measurements justify it.`;
    case 'mock-flaky':
      return `About ${t}: it depends on context, so keep it simple and check your assumptions.`;
    default: // mock-fast
      return `Short answer on ${t}: it depends on context, so keep it simple and check your assumptions.`;
  }
}

function usageFor(req, content) {
  const p = estimateRequestTokens(req);
  const c = estimateTokens(content);
  return { prompt_tokens: p, completion_tokens: c, total_tokens: p + c };
}

async function gate(model, signal) {
  const s = settings(model);
  const jitter = Math.random() * 0.2 * s.latencyMs;
  await sleep(Math.max(0, s.latencyMs + jitter), signal);
  if (Math.random() < s.failRate) {
    throw new GatewayError(502, 'upstream_error', `mock upstream failure (${model})`, { retryable: true });
  }
}

export function createMock(cfg = {}) {
  return {
    name: 'mock',
    available: () => true,
    async chat(req, model, { signal } = {}) {
      await gate(model, signal);
      const content = mockAnswer(req, model);
      return {
        id: `chatcmpl-${randomUUID()}`,
        object: 'chat.completion',
        created: Math.floor(Date.now() / 1000),
        model,
        choices: [{ index: 0, message: { role: 'assistant', content }, finish_reason: 'stop' }],
        usage: usageFor(req, content),
      };
    },
    async *chatStream(req, model, { signal } = {}) {
      // Fail/latency gate applies before the first chunk so failover can still happen.
      await gate(model, signal);
      const content = mockAnswer(req, model);
      const id = `chatcmpl-${randomUUID()}`;
      const created = Math.floor(Date.now() / 1000);
      const base = { id, object: 'chat.completion.chunk', created, model };
      const words = content.split(' ');
      yield { ...base, choices: [{ index: 0, delta: { role: 'assistant', content: '' }, finish_reason: null }] };
      for (let i = 0; i < words.length; i++) {
        await sleep(cfg.chunkDelayMs ?? 8, signal);
        yield { ...base, choices: [{ index: 0, delta: { content: (i ? ' ' : '') + words[i] }, finish_reason: null }] };
      }
      yield { ...base, choices: [{ index: 0, delta: {}, finish_reason: 'stop' }], usage: usageFor(req, content) };
    },
  };
}
