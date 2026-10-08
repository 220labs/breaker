// Builds the provider map from config.providers. The key is the provider name used in target
// ids ("groq/llama-3"); `type` picks the implementation and defaults to the key, and any
// entry with a baseUrl and no known type is treated as OpenAI-compatible.
import { createMock } from './mock.js';
import { createOpenAI } from './openai.js';
import { createAnthropic } from './anthropic.js';
import { createGemini } from './gemini.js';
import { createOllama } from './ollama.js';

export { setChaos, getChaos } from './mock.js';

export function createProviders(config) {
  const out = new Map();
  for (const [name, cfg = {}] of Object.entries(config.providers ?? {})) {
    const type = cfg.type ?? name;
    let p;
    if (type === 'mock') p = createMock(cfg);
    else if (type === 'openai') p = createOpenAI(name, cfg);
    else if (type === 'anthropic') p = createAnthropic(cfg);
    else if (type === 'gemini') p = createGemini(cfg);
    else if (type === 'ollama') p = createOllama(cfg);
    else if (cfg.baseUrl) p = createOpenAI(name, cfg);
    else continue;
    out.set(name, { ...p, name });
  }
  return out;
}
