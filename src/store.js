import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

const json = (v) => (v == null ? null : typeof v === 'string' ? v : JSON.stringify(v));
const parse = (s) => { try { return s == null ? null : JSON.parse(s); } catch { return s; } };

export function createStore(dbPath = ':memory:') {
  if (dbPath !== ':memory:') mkdirSync(dirname(dbPath), { recursive: true });
  const db = new DatabaseSync(dbPath);
  db.exec(`
    CREATE TABLE IF NOT EXISTS requests (
      id TEXT, ts INTEGER, keyId TEXT, alias TEXT, model TEXT, target TEXT, status INTEGER,
      latencyMs REAL, promptTokens INTEGER, completionTokens INTEGER, costUsd REAL, savedUsd REAL,
      cache TEXT, attempts TEXT, guardrails TEXT, error TEXT
    );
    CREATE INDEX IF NOT EXISTS requests_ts ON requests(ts);
    CREATE INDEX IF NOT EXISTS requests_key ON requests(keyId, ts);
    CREATE TABLE IF NOT EXISTS shadow (
      id TEXT, ts INTEGER, name TEXT, alias TEXT, primaryTarget TEXT, candidateTarget TEXT,
      primaryLatencyMs REAL, candidateLatencyMs REAL, primaryCostUsd REAL, candidateCostUsd REAL,
      score REAL, candidateError TEXT, prompt TEXT, primaryText TEXT, candidateText TEXT
    );
    CREATE INDEX IF NOT EXISTS shadow_name ON shadow(name, ts);
  `);

  const insReq = db.prepare(`INSERT INTO requests VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);
  const insShadow = db.prepare(`INSERT INTO shadow VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);
  const n = (v) => (v == null ? null : v);

  return {
    logRequest(r) {
      insReq.run(r.id ?? null, r.ts ?? Date.now(), n(r.keyId), n(r.alias), n(r.model), n(r.target), n(r.status),
        n(r.latencyMs), r.promptTokens ?? 0, r.completionTokens ?? 0, r.costUsd ?? 0, r.savedUsd ?? 0,
        r.cache ?? 'miss', json(r.attempts), json(r.guardrails), n(r.error));
    },
    recent(limit = 50) {
      return db.prepare('SELECT * FROM requests ORDER BY ts DESC, rowid DESC LIMIT ?').all(limit).map((row) => ({
        ...row, attempts: parse(row.attempts), guardrails: parse(row.guardrails),
      }));
    },
    summary() {
      const t = db.prepare(`SELECT COUNT(*) requests, COALESCE(SUM(status >= 400),0) errors, COALESCE(SUM(costUsd),0) costUsd,
        COALESCE(SUM(promptTokens + completionTokens),0) tokens, COALESCE(SUM(cache IN ('exact','semantic')),0) cacheHits,
        COALESCE(SUM(savedUsd),0) savedUsd FROM requests`).get();
      const byKey = db.prepare(`SELECT keyId, COUNT(*) requests, COALESCE(SUM(costUsd),0) costUsd,
        COALESCE(SUM(promptTokens + completionTokens),0) tokens, COALESCE(SUM(status >= 400),0) errors
        FROM requests GROUP BY keyId ORDER BY requests DESC`).all();
      const byTarget = db.prepare(`SELECT target, COUNT(*) requests, COALESCE(SUM(status >= 400),0) errors,
        COALESCE(AVG(latencyMs),0) avgLatencyMs, COALESCE(SUM(costUsd),0) costUsd
        FROM requests WHERE target IS NOT NULL GROUP BY target ORDER BY requests DESC`).all();
      const since = Date.now() - 30 * 60_000;
      const perMinute = db.prepare(`SELECT (ts / 60000) * 60000 minute, COUNT(*) requests,
        COALESCE(SUM(status >= 400),0) errors, COALESCE(SUM(costUsd),0) costUsd
        FROM requests WHERE ts >= ? GROUP BY ts / 60000 ORDER BY minute`).all(since);
      const plain = (o) => ({ ...o });
      return { totals: plain(t), byKey: byKey.map(plain), byTarget: byTarget.map(plain), perMinute: perMinute.map(plain) };
    },
    spendSince(keyId, sinceMs) {
      return db.prepare('SELECT COALESCE(SUM(costUsd),0) s FROM requests WHERE keyId = ? AND ts >= ?').get(keyId, sinceMs).s;
    },
    logShadow(r) {
      insShadow.run(r.id ?? null, r.ts ?? Date.now(), n(r.name), n(r.alias), n(r.primaryTarget), n(r.candidateTarget),
        n(r.primaryLatencyMs), n(r.candidateLatencyMs), r.primaryCostUsd ?? 0, r.candidateCostUsd ?? 0,
        n(r.score), n(r.candidateError), n(r.prompt), n(r.primaryText), n(r.candidateText));
    },
    shadowRecords(name, limit = 500) {
      const rows = name
        ? db.prepare('SELECT * FROM shadow WHERE name = ? ORDER BY ts DESC, rowid DESC LIMIT ?').all(name, limit)
        : db.prepare('SELECT * FROM shadow ORDER BY ts DESC, rowid DESC LIMIT ?').all(limit);
      return rows.map((r) => ({ ...r }));
    },
    close() { db.close(); },
  };
}
