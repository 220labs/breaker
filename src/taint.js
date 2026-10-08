// Session taint firewall: once a session holds untrusted tool output (an email, a web page),
// any model-proposed call to a sink tool (send, post, write, run) is blocked, held for approval
// or flagged. Evidence: argument values that appear verbatim in the untrusted text.

const DEFAULT_SINKS = ['send_email', 'http_request', 'http_post', 'post_message', 'bash', 'write_file', 'transfer_funds', 'create_webhook'];

const INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts?)/i,
  /\byou\s+are\s+now\b/i,
  /system\s+prompt/i,
  /new\s+instructions\s*:/i,
  /important\s*:?\s*(new\s+instructions|assistant\s+must|ai\s+assistant)/i,
  /\b(forward|send|email|post)\b[^.]{0,120}?\bto\b\s+[^\s,]*(@|https?:\/\/)/i,
  /exfiltrate/i,
];

export function looksLikeInjection(text) {
  const s = String(text ?? '');
  return INJECTION_PATTERNS.some((re) => re.test(s));
}

const textOf = (c) => {
  if (typeof c === 'string') return c;
  if (Array.isArray(c)) return c.map((p) => (typeof p === 'string' ? p : p?.text || '')).join('\n');
  return '';
};

export function createTaint(config) {
  const cfg = config?.taint || {};
  const mode = ['block', 'approve', 'flag'].includes(cfg.mode) ? cfg.mode : 'block';
  // Tool names match case-insensitively: Claude Code says `Bash`, other agents `bash`.
  const lc = (x) => String(x ?? '').toLowerCase();
  const sources = (cfg.sources || ['*']).map(lc);
  const trusted = new Set((cfg.trustedTools || []).map(lc));
  const sinks = new Set((cfg.sinks || DEFAULT_SINKS).map((x) => String(x).toLowerCase()));
  const untrusted = (tool) => (sources.includes('*') || sources.includes(lc(tool))) && !trusted.has(lc(tool));

  function analyze(body, format = 'anthropic') {
    const names = new Map();
    const results = [];
    for (const m of body?.messages || []) {
      if (format === 'openai') {
        for (const tc of m.tool_calls || []) names.set(tc.id, tc.function?.name);
        if (m.role === 'tool') results.push({ id: m.tool_call_id, text: textOf(m.content) });
      } else if (Array.isArray(m.content)) {
        for (const b of m.content) {
          if (b?.type === 'tool_use') names.set(b.id, b.name);
          else if (b?.type === 'tool_result') results.push({ id: b.tool_use_id, text: textOf(b.content) });
        }
      }
    }
    const srcs = [];
    for (const r of results) {
      const tool = names.get(r.id) || 'unknown';
      if (!untrusted(tool)) continue;
      srcs.push({ tool, toolUseId: r.id, excerpt: r.text.slice(0, 160), injection: looksLikeInjection(r.text), text: r.text });
    }
    return { tainted: srcs.length > 0, sources: srcs, untrustedText: srcs.map((s) => s.text).join('\n') };
  }

  function evidenceFor(input, taint) {
    const out = [];
    const walk = (v, path) => {
      if (typeof v === 'string') {
        if (v.length < 6) return;
        const src = taint.sources.find((s) => s.text.includes(v));
        if (src) out.push(`${path} "${v.length > 80 ? v.slice(0, 80) + '...' : v}" appears in untrusted output of ${src.tool}`);
      } else if (Array.isArray(v)) v.forEach((x, i) => walk(x, `${path}[${i}]`));
      else if (v && typeof v === 'object') for (const [k, x] of Object.entries(v)) walk(x, `${path}.${k}`);
    };
    walk(input, 'input');
    return out;
  }

  function enforce(body, response, format = 'anthropic', { approved } = {}) {
    const out = structuredClone(response);
    const decisions = [];
    const taint = analyze(body, format);
    const calls = [];
    if (format === 'openai') {
      for (const tc of out?.choices?.[0]?.message?.tool_calls || []) {
        let input = {};
        try { input = JSON.parse(tc.function?.arguments || '{}'); } catch { /* leave empty */ }
        calls.push({ id: tc.id, name: tc.function?.name, input });
      }
    } else {
      for (const b of out?.content || []) if (b?.type === 'tool_use') calls.push({ id: b.id, name: b.name, input: b.input });
    }
    const removed = new Map(); // id -> replacement text
    for (const c of calls) {
      if (!taint.tainted || !sinks.has(lc(c.name))) {
        decisions.push({ tool: c.name, action: 'allow', reason: taint.tainted ? 'not a sink tool' : 'session has no untrusted content', evidence: [] });
        continue;
      }
      if (approved?.has(c.id)) {
        decisions.push({ tool: c.name, action: 'allow', reason: 'approved by operator', evidence: [] });
        continue;
      }
      const evidence = evidenceFor(c.input, taint);
      const from = [...new Set(taint.sources.map((s) => s.tool))].map((t) => `\`${t}\``).join(', ');
      const inj = taint.sources.some((s) => s.injection);
      const reason = `sink tool in a session with untrusted content from ${from}${inj ? ' that looks like a prompt injection' : ''}`
        + (evidence.length ? '; argument derived from untrusted content' : '');
      decisions.push({ tool: c.name, action: mode, reason, evidence });
      if (mode === 'flag') continue;
      removed.set(c.id, `[breaker] ${mode === 'approve' ? 'Held' : 'Blocked'} tool call \`${c.name}\`: this session contains untrusted content from ${from}${inj ? ' that looks like a prompt injection' : ''}; the call would send data outside.`
        + (evidence.length ? ` Evidence: ${evidence.join('; ')}.` : '')
        + ` An operator can approve it with x-gateway-approve: ${c.id}.`);
    }
    if (removed.size) {
      if (format === 'openai') {
        const msg = out.choices[0].message;
        msg.tool_calls = msg.tool_calls.filter((tc) => !removed.has(tc.id));
        const note = [...removed.values()].join('\n');
        msg.content = msg.content ? `${msg.content}\n${note}` : note;
        if (!msg.tool_calls.length) { delete msg.tool_calls; out.choices[0].finish_reason = 'stop'; }
      } else {
        out.content = out.content.map((b) => (b?.type === 'tool_use' && removed.has(b.id) ? { type: 'text', text: removed.get(b.id) } : b));
        if (!out.content.some((b) => b?.type === 'tool_use')) out.stop_reason = 'end_turn';
      }
    }
    return { response: out, decisions };
  }

  return { analyze, enforce };
}
