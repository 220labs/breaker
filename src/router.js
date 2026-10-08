// Routing: alias -> ordered targets (strategy), failover on retryable errors, fallback aliases,
// a circuit breaker per target. Streams fail over only before the first chunk.
import { GatewayError } from './errors.js';

const OPEN_AFTER = 3;
const HALF_OPEN_MS = 15_000;
const EWMA_ALPHA = 0.3;

function parseTarget(id) {
  const i = id.indexOf('/');
  if (i < 1 || i === id.length - 1) return null;
  return { provider: id.slice(0, i), model: id.slice(i + 1), id };
}

export function createRouter(config, providers) {
  const stats = new Map(); // targetId -> breaker + latency stats
  const rr = new Map();    // alias -> round-robin counter

  const stat = (id) => {
    let s = stats.get(id);
    if (!s) {
      s = { id, open: false, openedAt: 0, probing: false, consecutive: 0, ewma: 0, successes: 0, failures: 0, lastError: null };
      stats.set(id, s);
    }
    return s;
  };
  const stateOf = (s) => (!s.open ? 'closed' : Date.now() - s.openedAt >= HALF_OPEN_MS ? 'half-open' : 'open');

  // May this target be tried now? Half-open admits exactly one probe at a time.
  const admit = (s) => {
    const st = stateOf(s);
    if (st === 'closed') return true;
    if (st === 'half-open' && !s.probing) { s.probing = true; return true; }
    return false;
  };
  const succeed = (s, ms) => {
    s.open = false; s.probing = false; s.consecutive = 0; s.successes++;
    s.ewma = s.ewma ? EWMA_ALPHA * ms + (1 - EWMA_ALPHA) * s.ewma : ms;
  };
  const fail = (s, err) => {
    s.failures++; s.consecutive++; s.probing = false;
    s.lastError = err.message;
    if (s.open || s.consecutive >= OPEN_AFTER) { s.open = true; s.openedAt = Date.now(); }
  };

  function aliasTargets(name, alias) {
    const entries = (alias.targets ?? []).map((t) => (typeof t === 'string' ? { id: t, weight: 1 } : { id: t.id, weight: t.weight ?? 1 }));
    switch (alias.strategy ?? 'priority') {
      case 'weighted': {
        const pool = [...entries];
        const out = [];
        while (pool.length) {
          const total = pool.reduce((n, e) => n + e.weight, 0);
          let r = Math.random() * total;
          let i = pool.findIndex((e) => (r -= e.weight) < 0);
          if (i < 0) i = pool.length - 1;
          out.push(pool.splice(i, 1)[0]);
        }
        return out.map((e) => e.id);
      }
      case 'round-robin': {
        const n = rr.get(name) ?? 0;
        rr.set(name, n + 1);
        const k = entries.length ? n % entries.length : 0;
        return [...entries.slice(k), ...entries.slice(0, k)].map((e) => e.id);
      }
      case 'least-latency':
        // Never-measured targets sort first (ewma 0), so every target gets sampled.
        return entries.map((e, i) => ({ e, i, l: stat(e.id).ewma })).sort((a, b) => a.l - b.l || a.i - b.i).map((x) => x.e.id);
      default:
        return entries.map((e) => e.id);
    }
  }

  function resolve(modelName) {
    const alias = config.models?.[modelName];
    if (alias) {
      const targets = aliasTargets(modelName, alias).map(parseTarget).filter(Boolean);
      return { alias: modelName, targets };
    }
    const direct = typeof modelName === 'string' ? parseTarget(modelName) : null;
    if (direct && providers.has(direct.provider)) return { alias: null, targets: [direct] };
    throw new GatewayError(404, 'model_not_found', `model '${modelName}' not found`);
  }

  // Full ordered plan: the alias's targets, then each fallback alias (depth-first, once each).
  function plan(modelName) {
    const seen = new Set();
    const ids = new Set();
    const targets = [];
    const walk = (name) => {
      if (seen.has(name)) return;
      seen.add(name);
      const r = resolve(name);
      for (const t of r.targets) if (!ids.has(t.id)) { ids.add(t.id); targets.push(t); }
      for (const fb of config.models?.[name]?.fallback ?? []) {
        if (config.models?.[fb]) walk(fb);
      }
    };
    const first = resolve(modelName);
    seen.add(modelName);
    for (const t of first.targets) { ids.add(t.id); targets.push(t); }
    for (const fb of config.models?.[modelName]?.fallback ?? []) if (config.models?.[fb]) walk(fb);
    return targets;
  }

  const wrap = (err) =>
    err instanceof GatewayError ? err : new GatewayError(502, 'upstream_error', err?.message ?? String(err), { retryable: true });
  const retryable = (err) => err.extra?.retryable === true;

  function finalError(attempts, last) {
    const status = last?.status ?? 502;
    const e = new GatewayError(status >= 400 ? status : 502, 'all_targets_failed',
      attempts.length ? `all targets failed; last error: ${last?.message}` : 'no available target for this model',
      { retryable: false });
    if (!attempts.length) { e.status = 503; e.code = 'no_available_target'; }
    e.attempts = attempts;
    return e;
  }

  // Shared failover loop. `run(target, provider, signal)` returns the successful value.
  async function failover(req, signal, onAttempt, run) {
    const attempts = [];
    let last = null;
    for (const target of plan(req.model)) {
      const provider = providers.get(target.provider);
      if (!provider || !provider.available()) continue;
      const s = stat(target.id);
      if (!admit(s)) continue;
      const t0 = Date.now();
      try {
        const value = await run(target, provider);
        const latencyMs = Date.now() - t0;
        succeed(s, latencyMs);
        const a = { target: target.id, ok: true, status: 200, error: null, latencyMs };
        attempts.push(a); onAttempt?.(a);
        return { value, target, attempts };
      } catch (raw) {
        const err = wrap(raw);
        const latencyMs = Date.now() - t0;
        if (err.status === 499) { s.probing = false; } else fail(s, err);
        const a = { target: target.id, ok: false, status: err.status, error: err.message, latencyMs };
        attempts.push(a); onAttempt?.(a);
        last = err;
        if (!retryable(err)) { err.attempts = attempts; throw err; }
      }
    }
    throw finalError(attempts, last);
  }

  async function route(req, { signal, onAttempt } = {}) {
    const { value, target, attempts } = await failover(req, signal, onAttempt, (t, p) => p.chat({ ...req, stream: false }, t.model, { signal }));
    return { response: value, target, attempts };
  }

  async function routeStream(req, { signal, onAttempt } = {}) {
    const { value, target, attempts } = await failover(req, signal, onAttempt, async (t, p) => {
      const it = p.chatStream({ ...req, stream: true }, t.model, { signal })[Symbol.asyncIterator]();
      const first = await it.next(); // failover is still possible until this resolves
      return { it, first };
    });
    const { it, first } = value;
    const s = stat(target.id);
    async function* stream() {
      try {
        if (first.done) return;
        yield first.value;
        for (;;) {
          const n = await it.next();
          if (n.done) return;
          yield n.value;
        }
      } catch (raw) {
        const err = wrap(raw);
        if (err.status !== 499) fail(s, err);
        throw err;
      } finally {
        try { await it.return?.(); } catch {}
      }
    }
    return { target, stream: stream(), attempts };
  }

  async function callTarget(targetId, req, { signal } = {}) {
    const target = parseTarget(targetId);
    const provider = target && providers.get(target.provider);
    if (!provider) throw new GatewayError(404, 'model_not_found', `target '${targetId}' not found`);
    if (!provider.available()) throw new GatewayError(503, 'provider_unavailable', `provider '${target.provider}' is not available`);
    const t0 = Date.now();
    const response = await provider.chat({ ...req, stream: false }, target.model, { signal });
    return { response, latencyMs: Date.now() - t0 };
  }

  function health() {
    const ids = new Set(stats.keys());
    for (const a of Object.values(config.models ?? {})) {
      for (const t of a.targets ?? []) ids.add(typeof t === 'string' ? t : t.id);
    }
    return [...ids].map((id) => {
      const s = stat(id);
      return { id, state: stateOf(s), ewmaLatencyMs: Math.round(s.ewma), successes: s.successes, failures: s.failures, lastError: s.lastError };
    });
  }

  return { resolve, route, routeStream, callTarget, health };
}
