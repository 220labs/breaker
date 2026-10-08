import { createHash, randomUUID } from 'node:crypto';
import { embed, cosine } from './embed.js';
import { messageText } from './tokens.js';

export function createCache(config = {}) {
  const c = config.cache ?? {};
  const enabled = c.enabled !== false;
  const ttlMs = (c.ttlSeconds ?? 3600) * 1000;
  const semantic = c.semantic !== false;
  const threshold = c.threshold ?? 0.92;
  const MAX = 1000;
  const entries = new Map(); // key -> entry, insertion order = age
  const stats = { hits: 0, semanticHits: 0, misses: 0 };

  const cacheable = (req) => enabled && !req.stream && (req.temperature === 0 || req.temperature == null);
  const normMessages = (req) => (req.messages ?? []).map((m) => ({ role: m.role, content: messageText(m.content) }));
  const keyOf = (req) =>
    createHash('sha256')
      .update(JSON.stringify({ model: req.model, messages: normMessages(req), temperature: req.temperature ?? 0 }))
      .digest('hex');
  const prefixKey = (req) => JSON.stringify([req.model, normMessages(req).slice(0, -1)]);
  const lastText = (req) => {
    const ms = normMessages(req);
    for (let i = ms.length - 1; i >= 0; i--) if (ms[i].role === 'user') return ms[i].content;
    return ms.length ? ms[ms.length - 1].content : '';
  };
  const fresh = (resp) => ({ ...JSON.parse(JSON.stringify(resp)), id: 'chatcmpl-' + randomUUID().replace(/-/g, '').slice(0, 24) });

  function expire(now) {
    for (const [k, e] of entries) if (e.expires <= now) entries.delete(k);
  }

  return {
    get(req) {
      if (!cacheable(req)) return null;
      const now = Date.now();
      expire(now);
      const exact = entries.get(keyOf(req));
      if (exact) {
        stats.hits++;
        return { response: fresh(exact.response), kind: 'exact', similarity: 1 };
      }
      if (semantic) {
        const pk = prefixKey(req);
        const q = embed(lastText(req));
        let best = null, bestSim = 0;
        for (const e of entries.values()) {
          if (e.prefix !== pk) continue;
          const s = cosine(q, e.vec);
          if (s > bestSim) { bestSim = s; best = e; }
        }
        if (best && bestSim >= threshold) {
          stats.hits++;
          stats.semanticHits++;
          return { response: fresh(best.response), kind: 'semantic', similarity: bestSim };
        }
      }
      stats.misses++;
      return null;
    },
    set(req, response) {
      if (!cacheable(req)) return;
      const key = keyOf(req);
      entries.delete(key); // re-insert as newest
      entries.set(key, {
        response: JSON.parse(JSON.stringify(response)),
        expires: Date.now() + ttlMs,
        prefix: prefixKey(req),
        vec: embed(lastText(req)),
      });
      while (entries.size > MAX) entries.delete(entries.keys().next().value);
    },
    stats() {
      expire(Date.now());
      return { ...stats, size: entries.size };
    },
  };
}
