# breaker — interface contract

An open-source, self-hosted model gateway: one OpenAI-compatible endpoint in front of many
model providers, with routing, failover, keys, quotas, budgets, caching, guardrails, cost
tracking and a dashboard. Plus the feature the hosted gateways don't offer: **shadow
evaluation** — mirror a sample of live traffic to a candidate model, judge the answers
side by side, and report agreement, latency and projected savings before you switch.

Node >= 22, ES modules, **zero npm dependencies** (built-in `http`, `fetch`, `node:sqlite`,
`node:test`, `node:crypto`). Every module exports a factory; no module-level state except
in `providers/mock.js` chaos settings.

## Shared shapes

- **ChatRequest** = OpenAI chat-completions body:
  `{ model, messages: [{role, content}], max_tokens?, temperature?, stream?, user?, metadata? }`.
  `content` is a string (multi-part arrays: join the text parts).
- **ChatResponse** = OpenAI `chat.completion` object:
  `{ id, object: 'chat.completion', created, model, choices: [{index: 0, message: {role: 'assistant', content}, finish_reason}], usage: {prompt_tokens, completion_tokens, total_tokens} }`.
- **Chunk** = OpenAI `chat.completion.chunk` object; the final chunk carries `usage`.
- **Target** = `{ provider, model }` — one concrete deployment, id string `provider/model`.
- **GatewayError** (`src/errors.js`): `new GatewayError(status, code, message, extra?)`.
  Throw it for anything that should reach the client as a JSON error.

## Config (`config.json`, see `config.example.json`)

```jsonc
{
  "port": 8787,
  "adminKey": "admin-demo-key",
  "providers": { "mock": {}, "openai": {"apiKeyEnv": "OPENAI_API_KEY"}, ... },
  "pricing": { "mock/mock-pro": {"input": 3.0, "output": 15.0}, ... },   // USD per 1M tokens
  "models": {                                    // public aliases clients send as `model`
    "smart": { "strategy": "priority", "targets": ["mock/mock-pro", "mock/mock-fast"], "fallback": ["fast"] },
    "fast":  { "strategy": "least-latency" | "weighted" | "round-robin" | "priority",
               "targets": ["mock/mock-fast", {"id": "mock/mock-alt", "weight": 2}] }
  },
  "keys": [ { "id": "team-web", "key": "gw-web-123", "models": ["*"] | ["fast"],
              "rpm": 60, "tpm": 100000, "budgetUsd": 5.0, "budgetPeriod": "day",
              "onBudget": "deny" | "downgrade", "downgradeTo": "fast" } ],
  "guardrails": { "pii": "redact" | "block" | "off", "blockedTerms": ["..."],
                  "promptInjection": "flag" | "block" | "off", "maxInputTokens": 8000 },
  "cache": { "enabled": true, "ttlSeconds": 3600, "semantic": true, "threshold": 0.92 },
  "shadow": [ { "name": "pro-vs-fast", "alias": "smart", "candidate": "mock/mock-fast",
                "sampleRate": 1.0, "judge": "local" | "<alias or provider/model>" } ],
  "db": "data/gateway.db"
}
```

A client may also send `model: "provider/model"` directly (no alias), if the key allows `*`.

## Modules and owners

| File | Exports | Owner |
| --- | --- | --- |
| `src/errors.js`, `src/config.js`, `src/server.js`, `src/tokens.js` | wiring, HTTP | parent |
| `src/providers/{index,mock,openai,anthropic,gemini,ollama}.js`, `src/router.js` | providers, routing | worker A |
| `src/policy/{keys,ratelimit,budget}.js`, `src/guardrails.js` | policy, safety | worker B |
| `src/cache.js`, `src/store.js`, `src/pricing.js` | cache, logs, cost | worker C |
| `public/index.html` | dashboard + playground | worker D |
| `src/shadow.js` | shadow evaluation | worker E |

### providers (worker A)

```js
// src/providers/index.js
export function createProviders(config) // -> Map<name, Provider>, only providers listed in config.providers
// Provider:
//   name
//   available(): boolean                           // e.g. API key present
//   async chat(req, model, {signal}) -> ChatResponse   (response.model = model)
//   async *chatStream(req, model, {signal}) -> yields Chunk (last one has usage)
// Errors: throw GatewayError with status 502 (upstream error), 504 (timeout), 429 (upstream rate limit)
//   and extra.retryable = true|false.
```

`mock.js` must make the demo work with no API keys: models `mock-fast` (~150 ms, terse),
`mock-pro` (~700 ms, fuller answer), `mock-alt` (~300 ms), `mock-flaky` (fails 50 %).
Deterministic answers derived from the last user message (different wording per model so
shadow comparison has something to judge). Token counts via `src/tokens.js` `estimateTokens(text)`.
Chaos control: `export function setChaos(model, {failRate, latencyMs})`, `export function getChaos()`.

```js
// src/router.js
export function createRouter(config, providers)
// -> {
//   resolve(modelName) -> {alias|null, targets: Target[]}     // throws GatewayError(404) unknown model
//   async route(req, {signal, onAttempt}) -> { response, target, attempts: [{target, ok, status, error, latencyMs}] }
//   async routeStream(req, {signal}) -> { target, stream: AsyncIterable<Chunk>, attempts }  // failover before first chunk only
//   async callTarget(targetId, req) -> { response, latencyMs }  // direct, no failover (used by shadow)
//   health() -> [{ id, state: 'closed'|'open'|'half-open', ewmaLatencyMs, successes, failures, lastError }]
// }
```

Strategies order the alias's targets; then try each in order, retrying the next on a
retryable error; then the alias's `fallback` aliases. Circuit breaker per target: open
after 3 consecutive failures, half-open after 15 s. Skip unavailable providers.

### policy (worker B)

```js
// src/policy/keys.js
export function createKeys(config) // -> { authenticate(authorizationHeaderOrXApiKey) -> keyRecord, checkModel(keyRecord, modelName), list() }
//   authenticate throws GatewayError(401); checkModel throws GatewayError(403).
// src/policy/ratelimit.js
export function createRateLimiter() // -> { check(keyRecord, estTokens) , commit(keyRecord, actualTokens), snapshot() }
//   sliding 60 s window for rpm and tpm; check throws GatewayError(429, 'rate_limited', msg, {retryAfter})
// src/policy/budget.js
export function createBudget(config, store) // -> { check(keyRecord, modelName) -> {action: 'allow'|'downgrade', model} ; snapshot() }
//   spend comes from store.spendSince(keyId, sinceMs); onBudget 'deny' throws GatewayError(402, 'budget_exceeded')
// src/guardrails.js
export function createGuardrails(config)
// -> { inspectInput(req) -> {req, findings}, inspectOutput(response) -> {response, findings} }
//   findings: [{type: 'pii'|'blocked_term'|'prompt_injection'|'size', subtype, action: 'redact'|'block'|'flag', count}]
//   PII: email, phone, credit card (Luhn), IBAN, US SSN, API-key-looking secrets -> "[REDACTED:EMAIL]" etc.
//   block -> throw GatewayError(400, 'guardrail_blocked', msg, {findings})
```

### cache, store, pricing (worker C)

```js
// src/pricing.js
export function createPricing(config) // -> { cost(targetId, usage) -> usd number, table() }  (unknown model -> 0)
// src/cache.js
export function createCache(config)
// -> { get(req) -> {response, kind: 'exact'|'semantic', similarity} | null, set(req, response), stats() -> {hits, semanticHits, misses, size} }
//   key = model + messages (+ temperature). Only cache when temperature is 0 or unset.
//   semantic: local embedding (hashed word + char-trigram vectors, cosine) on the last user message,
//   same model and same earlier messages; threshold from config.
// src/store.js
export function createStore(dbPath)  // node:sqlite DatabaseSync; ':memory:' allowed
// -> { logRequest(rec), recent(limit=50), summary() , spendSince(keyId, sinceMs), logShadow(rec), shadowRecords(name?, limit) }
//   rec: {id, ts, keyId, alias, model (requested), target, status, latencyMs, promptTokens, completionTokens,
//         costUsd, cache: 'miss'|'exact'|'semantic', attempts (json), guardrails (json), error}
//   summary(): {totals: {requests, errors, costUsd, tokens, cacheHits, savedUsd}, byKey: [...], byTarget: [...], perMinute: [...last 30 min]}
```

### dashboard (worker D)

`public/index.html`, one self-contained file (inline CSS/JS, no CDN). Polls every 2 s:
`GET /admin/api/summary`, `/admin/api/requests`, `/admin/api/health`, `/admin/api/shadow`,
`/admin/api/keys`, `/admin/api/chaos`; admin key sent as header `x-admin-key` (asked once, kept
in localStorage, default `admin-demo-key`). Panels: totals tiles, requests table, per-target
health with circuit state, per-key spend vs budget and rate usage, cache stats, shadow
experiments, chaos switches (`POST /admin/api/chaos {model, failRate, latencyMs}`) and a playground
that posts to `/v1/chat/completions` with a chosen gateway key and model and shows the
response headers `x-gateway-*`.

### shadow (worker E)

```js
// src/shadow.js
export function createShadow(config, router, store, pricing)
// -> { maybeShadow(req, primary: {response, target, latencyMs, alias}) -> void   // fire-and-forget, never throws
//      report() -> [{name, alias, candidate, samples, agreement (0..1 mean), agreeRate (share >= 0.7),
//                     primaryP50Ms, candidateP50Ms, primaryCostUsd, candidateCostUsd, projectedSavingsPct,
//                     candidateErrors, verdict: 'switch'|'keep'|'collecting', examples: [...3 worst]}] }
//   judge 'local': similarity of the two answers (token-set + trigram cosine), no model call.
//   judge = model name: ask that model to score 0-10 for equivalence, parse the number; fall back to local.
//   verdict: samples >= 5 and agreeRate >= 0.8 and candidate cheaper -> 'switch'.
```

## HTTP (parent, `src/server.js`)

- `POST /v1/chat/completions` (Bearer gateway key), `GET /v1/models`, `GET /healthz`
- `GET /` dashboard; `/admin/api/*` (header `x-admin-key`)
- Response headers: `x-request-id`, `x-gateway-target`, `x-gateway-cache`, `x-gateway-cost-usd`,
  `x-gateway-attempts`, `x-gateway-guardrails`, `x-gateway-downgraded`.
- Error body: `{ error: { type: code, message, ...extra } }`.

## Tests

`node --test test/` — each owner writes `test/<area>.test.js` against its own module with
`:memory:` DBs and the mock provider; no network.
