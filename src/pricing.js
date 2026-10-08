// USD per 1M tokens, keyed "provider/model". config.pricing overrides these defaults.
const DEFAULTS = {
  'mock/mock-fast': { input: 0.15, output: 0.6 },
  'mock/mock-alt': { input: 0.5, output: 1.5 },
  'mock/mock-pro': { input: 3, output: 15 },
  'mock/mock-flaky': { input: 0.15, output: 0.6 },
  'openai/gpt-4o-mini': { input: 0.15, output: 0.6 },
  'openai/gpt-4o': { input: 2.5, output: 10 },
  'anthropic/claude-sonnet-5-5': { input: 3, output: 15 },
  'anthropic/claude-haiku-5-5': { input: 1, output: 5 },
  'gemini/gemini-2.5-flash': { input: 0.3, output: 2.5 },
  'gemini/gemini-2.5-pro': { input: 1.25, output: 10 },
};

export function createPricing(config = {}) {
  const prices = { ...DEFAULTS, ...(config.pricing ?? {}) };
  return {
    cost(targetId, usage = {}) {
      const p = prices[targetId];
      if (!p) return 0;
      const inTok = usage.prompt_tokens ?? 0;
      const outTok = usage.completion_tokens ?? 0;
      return (inTok * (p.input ?? 0) + outTok * (p.output ?? 0)) / 1e6;
    },
    table() {
      return JSON.parse(JSON.stringify(prices));
    },
  };
}
