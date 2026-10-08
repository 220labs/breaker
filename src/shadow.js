// Shadow evaluation: mirror a sample of live traffic to a candidate model, judge the answers
// side by side, and report agreement, latency and projected savings with a verdict.
import { randomUUID } from 'node:crypto';

const MAX_IN_FLIGHT = 4;
const SYSTEM_JUDGE = 'You compare two answers to the same question. Reply with only an integer 0-10: 10 = same meaning and quality, 0 = contradictory or wrong.';

// Built-in fallback when src/embed.js is not available: token-set Jaccard.
function jaccard(a, b) {
  const tok = (s) => new Set(String(s).toLowerCase().match(/[\p{L}\p{N}]+/gu) || []);
  const A = tok(a), B = tok(b);
  if (!A.size && !B.size) return 1;
  let inter = 0;
  for (const t of A) if (B.has(t)) inter++;
  return inter / (A.size + B.size - inter);
}

function textOf(content) {
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) return content.map((p) => (typeof p === 'string' ? p : p?.text || '')).join(' ');
  return '';
}
const answerOf = (res) => textOf(res?.choices?.[0]?.message?.content);
const lastUser = (req) => {
  const m = [...(req?.messages || [])].reverse().find((x) => x.role === 'user');
  return textOf(m?.content);
};
const clip = (s, n) => String(s ?? '').slice(0, n);

function median(xs) {
  if (!xs.length) return 0;
  const s = [...xs].sort((a, b) => a - b);
  const m = s.length >> 1;
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}
const sum = (xs) => xs.reduce((a, b) => a + b, 0);

export function createShadow(config, router, store, pricing, { similarity } = {}) {
  const experiments = Array.isArray(config?.shadow) ? config.shadow : [];
  const inflight = new Set();
  let simFn = similarity || null;
  let simLoaded = !!similarity;

  async function getSimilarity() {
    if (!simLoaded) {
      simLoaded = true;
      try {
        const mod = await import('./embed.js');
        if (typeof mod.similarity === 'function') simFn = mod.similarity;
      } catch { /* embed.js missing: use Jaccard */ }
    }
    return simFn || jaccard;
  }

  async function localScore(a, b) {
    const f = await getSimilarity();
    try {
      const v = Number(f(a, b));
      return Number.isFinite(v) ? Math.min(1, Math.max(0, v)) : jaccard(a, b);
    } catch { return jaccard(a, b); }
  }

  async function score(exp, prompt, primaryText, candidateText) {
    if (exp.judge && exp.judge !== 'local') {
      try {
        const out = await router.route({
          model: exp.judge,
          temperature: 0,
          messages: [
            { role: 'system', content: SYSTEM_JUDGE },
            { role: 'user', content: `Question:\n${prompt}\n\nAnswer A:\n${primaryText}\n\nAnswer B:\n${candidateText}` },
          ],
        });
        const m = answerOf(out?.response).match(/\d+/);
        if (m) return Math.min(10, Number(m[0])) / 10;
      } catch { /* fall through to local */ }
    }
    return localScore(primaryText, candidateText);
  }

  async function run(exp, req, primary) {
    const prompt = clip(lastUser(req), 300);
    const primaryText = answerOf(primary.response);
    const rec = {
      id: randomUUID(), ts: Date.now(), name: exp.name, alias: exp.alias, candidate: exp.candidate,
      judge: exp.judge || 'local', prompt, primaryTarget: primary.target,
      primaryText: clip(primaryText, 2000), candidateText: null, score: null,
      primaryLatencyMs: primary.latencyMs, candidateLatencyMs: null,
      primaryCostUsd: 0, candidateCostUsd: 0, candidateError: null,
    };
    try { rec.primaryCostUsd = pricing.cost(primary.target, primary.response?.usage) || 0; } catch { /* keep 0 */ }
    try {
      const { response, latencyMs } = await router.callTarget(exp.candidate, { ...req, stream: false });
      const candText = answerOf(response);
      rec.candidateText = clip(candText, 2000);
      rec.candidateLatencyMs = latencyMs;
      try { rec.candidateCostUsd = pricing.cost(exp.candidate, response?.usage) || 0; } catch { /* keep 0 */ }
      rec.score = await score(exp, prompt, primaryText, candText);
    } catch (e) {
      rec.candidateError = clip(e?.message || String(e), 500);
      rec.score = null;
    }
    store.logShadow(rec);
  }

  function maybeShadow(req, primary) {
    try {
      if (!req || !primary || req.stream) return;
      for (const exp of experiments) {
        if (exp.alias !== primary.alias || primary.target === exp.candidate) continue;
        if (!(Math.random() < (exp.sampleRate ?? 0))) continue;
        if (inflight.size >= MAX_IN_FLIGHT) return; // drop when over the cap
        const p = new Promise((resolve) => setImmediate(resolve))
          .then(() => run(exp, req, primary))
          .catch(() => {})
          .finally(() => inflight.delete(p));
        inflight.add(p);
      }
    } catch { /* never throws */ }
  }

  const pending = () => inflight.size;
  async function flush() {
    while (inflight.size) await Promise.allSettled([...inflight]);
  }

  function report() {
    return experiments.map((exp) => {
      let all = [];
      try { all = store.shadowRecords(exp.name, 500) || []; } catch { /* empty */ }
      const ok = all.filter((r) => !r.candidateError && typeof r.score === 'number');
      const n = ok.length;
      const primaryCostUsd = sum(ok.map((r) => r.primaryCostUsd || 0));
      const candidateCostUsd = sum(ok.map((r) => r.candidateCostUsd || 0));
      const agreement = n ? sum(ok.map((r) => r.score)) / n : 0;
      const agreeRate = n ? ok.filter((r) => r.score >= 0.7).length / n : 0;
      const projectedSavingsPct = primaryCostUsd > 0
        ? Math.round((1 - candidateCostUsd / primaryCostUsd) * 1000) / 10 : 0;
      let verdict = 'keep';
      if (n < 5) verdict = 'collecting';
      else if (agreeRate >= 0.8 && candidateCostUsd < primaryCostUsd) verdict = 'switch';
      return {
        name: exp.name, alias: exp.alias, candidate: exp.candidate, samples: n,
        agreement, agreeRate,
        primaryP50Ms: median(ok.map((r) => r.primaryLatencyMs || 0)),
        candidateP50Ms: median(ok.map((r) => r.candidateLatencyMs || 0)),
        primaryCostUsd, candidateCostUsd, projectedSavingsPct,
        candidateErrors: all.length - all.filter((r) => !r.candidateError).length,
        verdict,
        examples: [...ok].sort((a, b) => a.score - b.score).slice(0, 3)
          .map((r) => ({ prompt: r.prompt, primaryText: r.primaryText, candidateText: r.candidateText, score: r.score })),
      };
    });
  }

  return { maybeShadow, report, pending, flush };
}
