import { GatewayError } from '../errors.js';

export function periodStart(period, t = Date.now()) {
  const d = new Date(t);
  if (period === 'day') return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate());
  if (period === 'month') return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 1);
  return 0; // 'total'
}

// Per-key spend caps. Spend is read from the store, so it survives restarts.
export function createBudget(config, store, { now = Date.now } = {}) {
  const keys = config.keys ?? [];

  function spent(k) {
    return store.spendSince(k.id, periodStart(k.budgetPeriod ?? 'day', now())) ?? 0;
  }

  function check(keyRecord, modelName) {
    const budget = keyRecord.budgetUsd;
    if (budget == null) return { action: 'allow', model: modelName };
    const spentUsd = spent(keyRecord);
    const downgrade = keyRecord.onBudget === 'downgrade' && keyRecord.downgradeTo;
    if (spentUsd >= budget) {
      if (downgrade) return { action: 'downgrade', model: keyRecord.downgradeTo };
      throw new GatewayError(402, 'budget_exceeded',
        `Budget exceeded for key '${keyRecord.id}': $${spentUsd.toFixed(4)} of $${budget} per ${keyRecord.budgetPeriod ?? 'day'}`,
        { spentUsd, budgetUsd: budget });
    }
    // Soft downgrade: stretch the remaining 10% on the cheaper model.
    if (downgrade && spentUsd >= budget * 0.9 && modelName !== keyRecord.downgradeTo) {
      return { action: 'downgrade', model: keyRecord.downgradeTo };
    }
    return { action: 'allow', model: modelName };
  }

  function snapshot() {
    return keys.filter((k) => k.budgetUsd != null).map((k) => {
      const spentUsd = spent(k);
      return { keyId: k.id, spentUsd, budgetUsd: k.budgetUsd, period: k.budgetPeriod ?? 'day',
        pct: k.budgetUsd > 0 ? Math.round((spentUsd / k.budgetUsd) * 1000) / 10 : 0 };
    });
  }

  return { check, snapshot };
}
