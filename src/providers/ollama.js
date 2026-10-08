// Ollama through its OpenAI-compatible endpoint. Always "available": when the daemon is down
// the call fails as a retryable 502 and the router fails over / opens the breaker.
import { createOpenAI } from './openai.js';

export function createOllama(cfg = {}) {
  return createOpenAI('ollama', cfg, { baseUrl: 'http://localhost:11434/v1', apiKeyEnv: null, keyless: true });
}
