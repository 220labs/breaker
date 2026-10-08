import { GatewayError } from '../errors.js';

const WINDOW_MS = 60_000;

// Sliding 60 s window per key: one entry per request {t, tokens}. check() records the request
// with the estimated tokens and returns a ticket; commit() swaps the estimate for the actual
// count (ticket optional: without it the newest uncommitted entry of the key is adjusted).
export function createRateLimiter({ now = Date.now } = {}) {
  const windows = new Map(); // keyId -> [{t, tokens, committed}]

  function prune(id, t) {
    const w = (windows.get(id) ?? []).filter((e) => e.t > t - WINDOW_MS);
    windows.set(id, w);
    return w;
  }

  function check(keyRecord, estTokens = 0) {
    const t = now();
    const w = prune(keyRecord.id, t);
    const { rpm, tpm } = keyRecord;
    if (rpm && w.length >= rpm) {
      const retryAfter = Math.max(1, Math.ceil((w[0].t + WINDOW_MS - t) / 1000));
      throw new GatewayError(429, 'rate_limited', `Rate limit exceeded: ${rpm} requests per minute`, { retryAfter, limit: 'rpm' });
    }
    if (tpm) {
      let used = w.reduce((n, e) => n + e.tokens, 0);
      if (used + estTokens > tpm) {
        // Oldest entries age out first; wait until enough of them have.
        let retryAfter = 60;
        for (const e of w) {
          used -= e.tokens;
          if (used + estTokens <= tpm) { retryAfter = Math.max(1, Math.ceil((e.t + WINDOW_MS - t) / 1000)); break; }
        }
        throw new GatewayError(429, 'rate_limited', `Rate limit exceeded: ${tpm} tokens per minute`, { retryAfter, limit: 'tpm' });
      }
    }
    const entry = { t, tokens: estTokens, committed: false };
    w.push(entry);
    return entry;
  }

  function commit(keyRecord, actualTokens, ticket) {
    const w = windows.get(keyRecord.id) ?? [];
    const entry = ticket ?? [...w].reverse().find((e) => !e.committed);
    if (!entry) return;
    entry.tokens = actualTokens;
    entry.committed = true;
  }

  // keyRecord-less: snapshot needs rpm/tpm limits, which check() learns from the records it sees.
  const limits = new Map();
  const baseCheck = check;
  function trackedCheck(keyRecord, estTokens) {
    limits.set(keyRecord.id, { rpm: keyRecord.rpm, tpm: keyRecord.tpm });
    return baseCheck(keyRecord, estTokens);
  }

  function snapshot() {
    const t = now();
    return [...limits].map(([keyId, { rpm, tpm }]) => {
      const w = prune(keyId, t);
      return { keyId, rpmUsed: w.length, rpm: rpm ?? null, tpmUsed: w.reduce((n, e) => n + e.tokens, 0), tpm: tpm ?? null };
    });
  }

  return { check: trackedCheck, commit, snapshot };
}
