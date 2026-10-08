# breaker

> **An open-source project built as a joke during a Google AI event.** Google announced an Agent
> Gateway; this one was built in 30 minutes, on one laptop, by a handful of Claude agents. The joke
> is that it works: tested and running, it protects real agents (Claude Code included) from rogue
> prompts, and it can actually be used. MIT licensed.

breaker is a self-hosted agent gateway that sits between AI agents and the models they call, and protects the
agents from rogue prompts. Multi-vendor; Claude first. Zero npm dependencies (Node ≥ 22.5).

```sh
npm start            # http://localhost:8787  — dashboard at /, press "Run attack demo"
npm test             # 47 tests, no network
```

## Point an agent at it

| Agent | Setting |
| --- | --- |
| Claude Code | `ANTHROPIC_BASE_URL=http://localhost:8787 ANTHROPIC_CUSTOM_HEADERS="x-gateway-key: gw-cc-321" claude` — your own Claude login passes through; this key turns PII redaction off (Claude Code's own prompt carries emails) and keeps the taint firewall on |
| Anthropic SDK | `base_url="http://localhost:8787"`, `api_key="gw-web-123"` (set `ANTHROPIC_API_KEY` on the gateway) |
| OpenAI SDK, any vendor | `base_url="http://localhost:8787/v1"`, `api_key="gw-web-123"`, `model="smart"` |

## What it does

- **Two native wire formats, one pipeline**: Anthropic Messages (`/v1/messages`, streaming
  passthrough) and OpenAI chat completions (`/v1/chat/completions`) routed to Anthropic,
  OpenAI or any OpenAI-compatible endpoint, Gemini, Ollama, or the built-in mocks.
- **Agent identities**: a key per agent, model allowlists, requests and tokens per minute, budgets per day
  or month that deny or downgrade.
- **Guardrails** on input and output: PII and secret redaction (email, phone, card with Luhn,
  IBAN, SSN, API keys), direct prompt injection and jailbreak blocking, indirect injection in
  tool results flagged, blocked terms, size limits, secrets leaving through tool-call arguments.
- **Taint firewall** (the part hosted gateways don't do): once untrusted tool output (an email,
  a web page) enters an agent's context, calls to exfiltration-capable tools (`send_email`,
  `http_post`, `Bash`…) are held, with evidence when an argument was copied verbatim from the
  untrusted text. An operator approves a held call from the dashboard. Configure `taint.sources`,
  `taint.sinks`, `taint.trustedTools` in the config. A key can carry its own `guardrails` and
  `taint` objects, shallow-merged over the global ones (see `claude-code` in `config.example.json`).
- **Routing**: aliases with priority, weighted, round-robin or least-latency strategies,
  failover, fallback aliases and a circuit breaker per target; chaos switches for the demo.
- **Cost and cache**: per-model pricing, exact and semantic cache, sqlite audit log.
- **Model swap check**: mirror live traffic to a cheaper candidate and report agreement,
  latency and projected savings before switching.

Config: `config.example.json` (copy to `config.json`, which is gitignored). Contract between
modules: `SPEC.md`.

## Not yet

- No MCP or A2A proxying; the firewall reads the model's tool calls, not MCP traffic.
- Streamed replies in an untainted session pass through unbuffered; their token usage is read
  from the SSE events on the side and logged when the stream ends.
- Taint is coarse: any listed source taints the session until the end of the conversation.
