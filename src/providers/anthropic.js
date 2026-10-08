// Anthropic Messages API, translated to and from the OpenAI chat shape.
import { GatewayError } from '../errors.js';
import { messageText } from '../tokens.js';
import { postJson, combineSignals, toGatewayError, buildResponse, responseAsChunks, DEFAULT_TIMEOUT_MS } from './openai.js';

const STOP = { end_turn: 'stop', stop_sequence: 'stop', max_tokens: 'length', tool_use: 'tool_calls' };

export function createAnthropic(cfg = {}) {
  const baseUrl = (cfg.baseUrl ?? 'https://api.anthropic.com/v1').replace(/\/+$/, '');
  const apiKeyEnv = cfg.apiKeyEnv ?? 'ANTHROPIC_API_KEY';
  const key = () => process.env[apiKeyEnv] ?? cfg.apiKey;
  const chat = async (req, model, { signal } = {}) => {
    const system = (req.messages ?? []).filter((m) => m.role === 'system').map((m) => messageText(m.content)).join('\n\n');
    const messages = (req.messages ?? [])
      .filter((m) => m.role !== 'system')
      .map((m) => ({ role: m.role === 'assistant' ? 'assistant' : 'user', content: messageText(m.content) }));
    const body = { model, messages, max_tokens: req.max_tokens ?? 1024 };
    if (system) body.system = system;
    if (req.temperature !== undefined) body.temperature = req.temperature;
    const res = await postJson(`${baseUrl}/messages`, {
      headers: { 'x-api-key': key() ?? '', 'anthropic-version': '2023-06-01' },
      body, signal, timeoutMs: cfg.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    });
    let json;
    try { json = await res.json(); } catch (err) { throw toGatewayError(err, signal); }
    const text = (json.content ?? []).filter((b) => b.type === 'text').map((b) => b.text).join('');
    return buildResponse(model, text, STOP[json.stop_reason] ?? 'stop', {
      prompt_tokens: json.usage?.input_tokens ?? 0,
      completion_tokens: json.usage?.output_tokens ?? 0,
    });
  };
  return {
    name: 'anthropic',
    available: () => Boolean(key()),
    chat,
    async *chatStream(req, model, opts) {
      yield* responseAsChunks(await chat(req, model, opts));
    },
  };
}

// Raw passthrough for the native /v1/messages endpoint: body as-is, Response returned (non-2xx
// included). Auth is the gateway's own key when configured, otherwise the client's credentials.
export async function messagesUpstream(body, clientHeaders = {}, providerConfig = {}, { signal } = {}) {
  const base = (providerConfig.baseUrl ?? 'https://api.anthropic.com').replace(/\/+$/, '').replace(/\/v1$/, '');
  const h = (name) => {
    const v = clientHeaders[name] ?? clientHeaders[name.toLowerCase()];
    return Array.isArray(v) ? v.join(', ') : v;
  };
  const headers = { 'content-type': 'application/json', 'anthropic-version': h('anthropic-version') || '2023-06-01' };
  const ownKey = process.env[providerConfig.apiKeyEnv || 'ANTHROPIC_API_KEY'];
  if (ownKey) headers['x-api-key'] = ownKey;
  else {
    if (h('authorization')) headers.authorization = h('authorization');
    if (h('x-api-key')) headers['x-api-key'] = h('x-api-key');
  }
  if (h('anthropic-beta')) headers['anthropic-beta'] = h('anthropic-beta');
  try {
    return await fetch(`${base}/v1/messages`, {
      method: 'POST',
      headers,
      body: typeof body === 'string' || body instanceof Uint8Array ? body : JSON.stringify(body),
      signal: combineSignals(signal, 120_000),
    });
  } catch (err) {
    if (signal?.aborted) throw new GatewayError(499, 'client_closed', 'request aborted', { retryable: false });
    throw new GatewayError(502, 'upstream_unreachable', err?.cause?.code ?? err?.message ?? String(err), { retryable: true });
  }
}
