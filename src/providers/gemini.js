// Google Gemini generateContent (v1beta), translated to and from the OpenAI chat shape.
import { messageText } from '../tokens.js';
import { postJson, toGatewayError, buildResponse, responseAsChunks, DEFAULT_TIMEOUT_MS } from './openai.js';

const FINISH = { STOP: 'stop', MAX_TOKENS: 'length', SAFETY: 'content_filter', RECITATION: 'content_filter' };

export function createGemini(cfg = {}) {
  const baseUrl = (cfg.baseUrl ?? 'https://generativelanguage.googleapis.com/v1beta').replace(/\/+$/, '');
  const apiKeyEnv = cfg.apiKeyEnv ?? 'GEMINI_API_KEY';
  const key = () => process.env[apiKeyEnv] ?? cfg.apiKey;
  const chat = async (req, model, { signal } = {}) => {
    const system = (req.messages ?? []).filter((m) => m.role === 'system').map((m) => messageText(m.content)).join('\n\n');
    const contents = (req.messages ?? [])
      .filter((m) => m.role !== 'system')
      .map((m) => ({ role: m.role === 'assistant' ? 'model' : 'user', parts: [{ text: messageText(m.content) }] }));
    const body = { contents };
    if (system) body.systemInstruction = { parts: [{ text: system }] };
    const gen = {};
    if (req.max_tokens !== undefined) gen.maxOutputTokens = req.max_tokens;
    if (req.temperature !== undefined) gen.temperature = req.temperature;
    if (Object.keys(gen).length) body.generationConfig = gen;
    const url = `${baseUrl}/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(key() ?? '')}`;
    const res = await postJson(url, { body, signal, timeoutMs: cfg.timeoutMs ?? DEFAULT_TIMEOUT_MS });
    let json;
    try { json = await res.json(); } catch (err) { throw toGatewayError(err, signal); }
    const cand = json.candidates?.[0];
    const text = (cand?.content?.parts ?? []).map((p) => p.text ?? '').join('');
    return buildResponse(model, text, FINISH[cand?.finishReason] ?? 'stop', {
      prompt_tokens: json.usageMetadata?.promptTokenCount ?? 0,
      completion_tokens: json.usageMetadata?.candidatesTokenCount ?? 0,
    });
  };
  return {
    name: 'gemini',
    available: () => Boolean(key()),
    chat,
    async *chatStream(req, model, opts) {
      yield* responseAsChunks(await chat(req, model, opts));
    },
  };
}
