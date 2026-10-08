import { createHash, timingSafeEqual } from 'node:crypto';
import { GatewayError } from '../errors.js';

const digest = (s) => createHash('sha256').update(String(s)).digest();

// Gateway API keys from config.keys. Compared as sha256 digests with timingSafeEqual so the
// comparison time does not depend on how many leading characters match; every record is
// compared (no early exit) for the same reason.
export function createKeys(config) {
  const records = (config.keys ?? []).map((k) => ({ ...k, _digest: digest(k.key) }));

  function authenticate(header) {
    let presented = typeof header === 'string' ? header.trim() : '';
    const m = /^bearer\s+(.+)$/i.exec(presented);
    if (m) presented = m[1].trim();
    if (!presented) throw new GatewayError(401, 'invalid_api_key', 'Missing API key');
    const d = digest(presented);
    let found = null;
    for (const r of records) if (timingSafeEqual(d, r._digest) && !found) found = r;
    if (!found) throw new GatewayError(401, 'invalid_api_key', 'Invalid API key');
    const { _digest, ...rec } = found;
    return rec;
  }

  function checkModel(keyRecord, modelName) {
    const allowed = keyRecord.models ?? ['*'];
    if (allowed.includes('*') || allowed.includes(modelName)) return;
    throw new GatewayError(403, 'model_not_allowed', `Key '${keyRecord.id}' may not use model '${modelName}'`);
  }

  function list() {
    return records.map(({ _digest, key, ...rest }) => ({ ...rest, keyHint: `...${String(key).slice(-4)}` }));
  }

  return { authenticate, checkModel, list };
}
