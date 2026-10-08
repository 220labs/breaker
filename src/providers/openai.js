// OpenAI-compatible provider (OpenAI, Groq, Together, vLLM, Ollama ...): real HTTP via fetch.
// Also home of the small HTTP/response helpers the other real providers share.
import { randomUUID } from 'node:crypto';
import { GatewayError } from '../errors.js';
import { messageText } from '../tokens.js';

export const DEFAULT_TIMEOUT_MS = 30_000;

export function combineSignals(callerSignal, timeoutMs) {
  const t = AbortSignal.timeout(timeoutMs);
  return callerSignal ? AbortSignal.any([callerSignal, t]) : t;
}

// POST json; returns the Response on 2xx, otherwise throws GatewayError (429/5xx/timeout/network
// retryable, other 4xx not). Caller aborts are 499, never retried.
export async function postJson(url, { headers = {}, body, signal, timeoutMs = DEFAULT_TIMEOUT_MS }) {
  const sig = combineSignals(signal, timeoutMs);
  let res;
  try {
    res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...headers },
      body: JSON.stringify(body),
      signal: sig,
    });
  } catch (err) {
    throw toGatewayError(err, signal);
  }
  if (!res.ok) {
    let text = '';
    try { text = (await res.text()).slice(0, 500); } catch {}
    if (res.status === 429) throw new GatewayError(429, 'upstream_rate_limited', `upstream 429: ${text}`, { retryable: true });
    if (res.status >= 500) throw new GatewayError(502, 'upstream_error', `upstream ${res.status}: ${text}`, { retryable: true });
    const status = res.status === 401 || res.status === 403 ? 502 : res.status;
    throw new GatewayError(status, 'upstream_error', `upstream ${res.status}: ${text}`, { retryable: false });
  }
  return res;
}

export function toGatewayError(err, callerSignal) {
  if (err instanceof GatewayError) return err;
  if (callerSignal?.aborted) return new GatewayError(499, 'client_closed', 'request aborted', { retryable: false });
  if (err?.name === 'TimeoutError' || err?.name === 'AbortError') {
    return new GatewayError(504, 'upstream_timeout', 'upstream timed out', { retryable: true });
  }
  return new GatewayError(502, 'upstream_error', `upstream unreachable: ${err?.cause?.code ?? err?.message ?? err}`, { retryable: true });
}

export function buildResponse(model, content, finishReason, usage) {
  const p = usage?.prompt_tokens ?? 0;
  const c = usage?.completion_tokens ?? 0;
  return {
    id: `chatcmpl-${randomUUID()}`,
    object: 'chat.completion',
    created: Math.floor(Date.now() / 1000),
    model,
    choices: [{ index: 0, message: { role: 'assistant', content }, finish_reason: finishReason ?? 'stop' }],
    usage: { prompt_tokens: p, completion_tokens: c, total_tokens: p + c },
  };
}

// Providers without native streaming: yield one content chunk, then a usage chunk.
export function* responseAsChunks(resp) {
  const base = { id: resp.id, object: 'chat.completion.chunk', created: resp.created, model: resp.model };
  const ch = resp.choices[0];
  yield { ...base, choices: [{ index: 0, delta: { role: 'assistant', content: ch.message.content }, finish_reason: null }] };
  yield { ...base, choices: [{ index: 0, delta: {}, finish_reason: ch.finish_reason }], usage: resp.usage };
}

export function normalizeMessages(messages) {
  return (messages ?? []).map((m) => ({ ...m, content: messageText(m.content) }));
}

async function* sse(res, signal) {
  const dec = new TextDecoder();
  let buf = '';
  try {
    for await (const part of res.body) {
      buf += dec.decode(part, { stream: true });
      let idx;
      while ((idx = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, idx).trim();
        buf = buf.slice(idx + 1);
        if (!line.startsWith('data:')) continue;
        const data = line.slice(5).trim();
        if (data === '[DONE]') return;
        try { yield JSON.parse(data); } catch {}
      }
    }
  } catch (err) {
    throw toGatewayError(err, signal);
  }
}

export function createOpenAI(name, cfg = {}, defaults = {}) {
  const baseUrl = (cfg.baseUrl ?? defaults.baseUrl ?? 'https://api.openai.com/v1').replace(/\/+$/, '');
  const apiKeyEnv = cfg.apiKeyEnv ?? defaults.apiKeyEnv ?? 'OPENAI_API_KEY';
  const timeoutMs = cfg.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const keyless = defaults.keyless === true;
  const key = () => (apiKeyEnv ? process.env[apiKeyEnv] : undefined) ?? cfg.apiKey;
  const headers = () => ({ ...(key() ? { authorization: `Bearer ${key()}` } : {}), ...(cfg.headers ?? {}) });
  const body = (req, model, stream) => {
    const { metadata, ...rest } = req;
    return { ...rest, model, messages: normalizeMessages(req.messages), stream, ...(stream ? { stream_options: { include_usage: true } } : {}) };
  };
  return {
    name,
    available: () => keyless || Boolean(key()),
    async chat(req, model, { signal } = {}) {
      const res = await postJson(`${baseUrl}/chat/completions`, { headers: headers(), body: body(req, model, false), signal, timeoutMs });
      let json;
      try { json = await res.json(); } catch (err) { throw toGatewayError(err, signal); }
      return { ...json, model };
    },
    async *chatStream(req, model, { signal } = {}) {
      const res = await postJson(`${baseUrl}/chat/completions`, { headers: headers(), body: body(req, model, true), signal, timeoutMs });
      for await (const chunk of sse(res, signal)) yield { ...chunk, model };
    },
  };
}
