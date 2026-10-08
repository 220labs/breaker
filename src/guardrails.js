import { GatewayError } from './errors.js';
import { estimateRequestTokens, messageText } from './tokens.js';

function luhn(digits) {
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let n = Number(digits[digits.length - 1 - i]);
    if (i % 2 === 1) { n *= 2; if (n > 9) n -= 9; }
    sum += n;
  }
  return sum % 10 === 0;
}

// Order matters: each replacement removes its digits before the next detector runs, so a
// card number is not also reported as a phone number.
const DETECTORS = [
  { subtype: 'secret', re: /\b(?:sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,})/g },
  // Keeps the "api_key=" prefix (group 1) and redacts only the value.
  { subtype: 'secret', re: /\b((?:api[_-]?key|secret|token|password|passwd)["']?\s*[=:]\s*["']?)[A-Za-z0-9+/_=.-]{16,}/gi,
    replace: (m, prefix) => prefix },
  { subtype: 'email', re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b/g },
  { subtype: 'iban', re: /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b/g,
    valid: (m) => m.replace(/ /g, '').length >= 15 && m.replace(/ /g, '').length <= 34 && /\d/.test(m.slice(4)) },
  { subtype: 'ssn', re: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g },
  { subtype: 'credit_card', re: /\b\d(?:[ -]?\d){12,18}\b/g,
    valid: (m) => { const d = m.replace(/\D/g, ''); return d.length >= 13 && d.length <= 19 && luhn(d); } },
  // International needs a leading +; US formats need separators, so bare digit runs never match.
  { subtype: 'phone', re: /(?<![\w+])(?:\+\d{1,3}[\s.-]?)?(?:\(\d{3}\)\s?|\d{3}[\s.-])\d{3}[\s.-]\d{4}\b|(?<![\w+])\+\d{1,3}(?:[\s.-]?\(?\d{1,4}\)?){2,5}\b/g,
    valid: (m) => { const n = m.replace(/\D/g, '').length; return n >= 10 && n <= 15; } },
];

// Instruction-override attempts vs. role/limit-removal attempts; the subtype tells them apart.
const OVERRIDE = [
  /ignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|prompts|rules)/i,
  /disregard\s+(?:all\s+|any\s+)?(?:the\s+)?(?:above|previous|prior|earlier)/i,
  /reveal\s+(?:your\s+|the\s+)?(?:system|hidden)\s+prompt/i,
  /(?:print|show|repeat)\s+(?:your\s+|the\s+)?system\s+prompt/i,
  /forget\s+(?:all\s+|everything\s+)?(?:your\s+|the\s+)?(?:previous\s+|prior\s+)?instructions/i,
];
const JAILBREAK = [
  /you\s+are\s+now\s+(?:DAN\b|in\s+developer\s+mode)/i,
  /\bDAN\s+mode\b/i,
  /developer\s+mode/i,
  /no\s+(?:restrictions|limitations|filters)\b/i,
  /pretend\s+(?:that\s+)?you\s+(?:have\s+)?(?:no|don'?t\s+have\s+(?:any\s+)?)\s*(?:rules|restrictions|limits|guidelines)/i,
  /act\s+as\s+(?:an?\s+)?(?:unrestricted|unfiltered|uncensored)/i,
  /jailbreak/i,
];

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

export function createGuardrails(config) {
  const g = config.guardrails ?? config ?? {};
  const pii = g.pii ?? 'off';
  const injection = g.promptInjection ?? 'off';
  const terms = (g.blockedTerms ?? []).map((t) => ({ term: t, re: new RegExp(`(?<![\\w])${escapeRe(t)}(?![\\w])`, 'i') }));

  // Redacts one string; returns {text, counts: {subtype: n}}.
  function redact(text) {
    const counts = {};
    for (const d of DETECTORS) {
      text = text.replace(d.re, (m, ...rest) => {
        if (d.valid && !d.valid(m)) return m;
        counts[d.subtype] = (counts[d.subtype] ?? 0) + 1;
        const label = `[REDACTED:${d.subtype.toUpperCase()}]`;
        if (d.replace) return d.replace(m, rest[0]) + label;
        return label;
      });
    }
    return { text, counts };
  }

  const blocked = (findings, msg) => new GatewayError(400, 'guardrail_blocked', msg, { findings });

  // Findings are merged on (type, subtype, action, where) with a count.
  function addFinding(findings, f) {
    const hit = findings.find((x) => x.type === f.type && x.subtype === f.subtype && x.action === f.action && x.where === f.where);
    if (hit) hit.count += f.count ?? 1;
    else findings.push({ count: 1, ...f });
  }

  // Every scannable text of a request as {where, text, set(newText)}; set writes into `out`.
  // Images, tool_use blocks and all other block fields are left untouched.
  function segments(out, format) {
    const segs = [];
    if (format === 'anthropic') {
      if (typeof out.system === 'string') segs.push({ where: 'system', text: out.system, set: (t) => { out.system = t; } });
      else if (Array.isArray(out.system)) {
        for (const b of out.system) if (b?.type === 'text') segs.push({ where: 'system', text: b.text ?? '', set: (t) => { b.text = t; } });
      }
      for (const m of out.messages ?? []) {
        const where = m.role === 'assistant' ? 'assistant' : 'user';
        if (typeof m.content === 'string') { segs.push({ where, text: m.content, set: (t) => { m.content = t; } }); continue; }
        for (const b of Array.isArray(m.content) ? m.content : []) {
          if (b?.type === 'text') segs.push({ where, text: b.text ?? '', set: (t) => { b.text = t; } });
          else if (b?.type === 'tool_result') {
            if (typeof b.content === 'string') segs.push({ where: 'tool_result', text: b.content, set: (t) => { b.content = t; } });
            else for (const c of Array.isArray(b.content) ? b.content : []) {
              if (c?.type === 'text') segs.push({ where: 'tool_result', text: c.text ?? '', set: (t) => { c.text = t; } });
            }
          }
        }
      }
    } else {
      for (const m of out.messages ?? []) {
        const where = m.role === 'system' ? 'system' : m.role === 'assistant' ? 'assistant' : m.role === 'tool' ? 'tool_result' : 'user';
        const orig = messageText(m.content);
        // OpenAI content is written back as a string once redaction is on (multi-part arrays collapse).
        segs.push({ where, text: orig, set: (t) => { if (t !== orig || pii === 'redact') m.content = t; } });
      }
    }
    return segs;
  }

  function inspectInput(req, format = 'openai') {
    const out = structuredClone(req);
    const findings = [];
    const segs = segments(out, format);

    if (g.maxInputTokens) {
      const est = estimateRequestTokens({ messages: segs.map((s) => ({ content: s.text })) });
      if (est > g.maxInputTokens) {
        throw new GatewayError(400, 'input_too_large', `Input is about ${est} tokens; the limit is ${g.maxInputTokens}`,
          { findings: [{ type: 'size', subtype: 'max_input_tokens', action: 'block', where: 'user', count: 1 }] });
      }
    }

    for (const { term, re } of terms) {
      for (const sg of segs) if (re.test(sg.text)) addFinding(findings, { type: 'blocked_term', subtype: term, action: 'block', where: sg.where });
    }
    if (findings.length) throw blocked(findings, 'Request contains a blocked term');

    if (injection !== 'off') {
      let direct = false;
      for (const sg of segs) {
        for (const [subtype, list] of [['override', OVERRIDE], ['jailbreak', JAILBREAK]]) {
          if (!list.some((re) => re.test(sg.text))) continue;
          if (sg.where === 'tool_result') {
            // Indirect injection: never fails the request; the taint firewall handles tool results.
            addFinding(findings, { type: 'indirect_injection', subtype, action: 'flag', where: 'tool_result' });
          } else if (sg.where === 'assistant') {
            continue; // earlier assistant turns are our own output, not an attack surface
          } else {
            const action = injection === 'block' ? 'block' : 'flag';
            addFinding(findings, { type: 'prompt_injection', subtype, action, where: sg.where });
            if (action === 'block') direct = true;
          }
        }
      }
      if (direct) throw blocked(findings, 'Possible prompt injection detected');
    }

    if (pii !== 'off') {
      let found = false;
      for (const sg of segs) {
        const { text, counts } = redact(sg.text);
        for (const [subtype, count] of Object.entries(counts)) {
          found = true;
          addFinding(findings, { type: 'pii', subtype, action: pii === 'block' ? 'block' : 'redact', where: sg.where, count });
        }
        if (Object.keys(counts).length || pii === 'redact') sg.set(text);
      }
      if (found && pii === 'block') throw blocked(findings, 'Request contains personal data or secrets');
    }
    return { req: out, findings };
  }

  // Redacts every string inside a JSON value (tool_use input); returns counts by subtype.
  function redactDeep(v, counts) {
    if (typeof v === 'string') {
      const r = redact(v);
      for (const [k, n] of Object.entries(r.counts)) counts[k] = (counts[k] ?? 0) + n;
      return r.text;
    }
    if (Array.isArray(v)) return v.map((x) => redactDeep(x, counts));
    if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, redactDeep(x, counts)]));
    return v;
  }

  function inspectOutput(response, format = 'openai') {
    const out = structuredClone(response);
    const findings = [];
    if (pii === 'off') return { response: out, findings };
    const piiOf = (counts) => {
      for (const [subtype, count] of Object.entries(counts)) addFinding(findings, { type: 'pii', subtype, action: 'redact', where: 'assistant', count });
    };
    if (format === 'anthropic') {
      for (const b of Array.isArray(out.content) ? out.content : []) {
        if (b?.type === 'text' && typeof b.text === 'string') {
          const r = redact(b.text);
          b.text = r.text;
          piiOf(r.counts);
        } else if (b?.type === 'tool_use' && b.input != null) {
          const counts = {};
          b.input = redactDeep(b.input, counts);
          // A credential leaving through a tool call is its own finding; other PII is reported as pii.
          if (counts.secret) addFinding(findings, { type: 'secret_in_tool_call', subtype: 'secret', action: 'redact', where: 'assistant', count: counts.secret });
          delete counts.secret;
          piiOf(counts);
        }
      }
      return { response: out, findings };
    }
    for (const c of out.choices ?? []) {
      const content = c.message?.content;
      if (content == null) continue;
      const r = redact(messageText(content));
      piiOf(r.counts);
      if (Object.keys(r.counts).length) c.message.content = r.text;
    }
    return { response: out, findings };
  }

  return { inspectInput, inspectOutput };
}
