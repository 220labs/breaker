// Config: GATEWAY_CONFIG or ./config.json if present, else the committed demo config.
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

export function loadConfig() {
  const path = process.env.GATEWAY_CONFIG ?? [join(root, 'config.json'), join(root, 'config.example.json')].find(existsSync);
  const config = JSON.parse(readFileSync(path, 'utf8'));
  if (config.db && config.db !== ':memory:' && !config.db.startsWith('/')) config.db = join(root, config.db);
  return config;
}
