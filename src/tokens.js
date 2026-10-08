// Rough token estimate (~4 chars per token) — good enough for quotas and mock usage;
// real providers report their own usage, which wins wherever it is present.
export function estimateTokens(text) {
  if (!text) return 0;
  return Math.max(1, Math.ceil(String(text).length / 4));
}

export function messageText(content) {
  if (Array.isArray(content)) return content.map((p) => (typeof p === 'string' ? p : p.text ?? '')).join('');
  return content == null ? '' : String(content);
}

export function estimateRequestTokens(req) {
  return (req.messages ?? []).reduce((n, m) => n + estimateTokens(messageText(m.content)) + 4, 0);
}
