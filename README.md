# breaker

> **Released only as part of the film [220](https://220labs.dev/220/).** In its chapter five,
> Claude agents build this gateway in 29 minutes, on one laptop, during a Google Gemini workshop at
> which Google had just announced an Agent Gateway. The film's code is open, so this is too.
> **220 Labs cannot yet endorse it for production.** A Claude review on 2026-10-11 found what holds
> and what does not: [docs/review-2026-10-11.md](docs/review-2026-10-11.md). In its words, a
> working demonstration of these ideas, not a security boundary. If that evidence is enough for you
> to run it in production, we are not going to stop you; fix the first three findings first.
> MIT licensed. Page: [220labs.dev/220/breaker](https://220labs.dev/220/breaker/).

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
- **Guardrails** on input and output, all pattern matches (the review shows how easily they are
  beaten): PII and secret redaction in their usual formats (email, phone, card with Luhn, IBAN,
  SSN, API keys), common prompt-injection and jailbreak phrasings blocked, indirect injection in
  tool results flagged, blocked terms, size limits, secrets in non-streamed Anthropic tool-call
  arguments.
- **Taint firewall**: while untrusted tool output (an email, a web page) is in the request an
  agent sends, calls to exfiltration-capable tools (`send_email`,
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
- Taint is per request, not per session: it lasts only while the tainting tool result is still
  in the history the agent sends. Tool names match exactly, so an MCP-prefixed name is not a
  listed sink. Findings 1 to 10 of the review are all open.
