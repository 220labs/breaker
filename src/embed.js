// Local text embedding: hashed lowercase word unigrams + char trigrams of the content words,
// L2-normalised. No model call; good enough to tell paraphrases from unrelated text.
const DIM = 512;
const STOP = new Set(('a an the is are was were be been am s of to in on at for with and or it its this that what whats ' +
  'which who how do does did can could would should please tell me i you we my your about there their they them as by from ' +
  'give show').split(' '));
const W_WORD = 1.0;
const W_TRI = 0.5;

function hash(str) {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

function words(text) {
  return String(text ?? '').toLowerCase().replace(/[^\p{L}\p{N}]+/gu, ' ').trim().split(' ').filter(Boolean);
}

export function embed(text) {
  const v = new Float32Array(DIM);
  let ws = words(text);
  const content = ws.filter((w) => !STOP.has(w));
  if (content.length) ws = content; // all-stopword text keeps its words
  for (const w of ws) {
    v[hash('w:' + w) % DIM] += W_WORD;
    const padded = `^${w}$`;
    for (let i = 0; i + 3 <= padded.length; i++) v[hash('t:' + padded.slice(i, i + 3)) % DIM] += W_TRI;
  }
  let norm = 0;
  for (let i = 0; i < DIM; i++) norm += v[i] * v[i];
  norm = Math.sqrt(norm);
  if (norm > 0) for (let i = 0; i < DIM; i++) v[i] /= norm;
  return v;
}

export function cosine(a, b) {
  let dot = 0, na = 0, nb = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    na += a[i] * a[i];
    nb += b[i] * b[i];
  }
  return na && nb ? dot / Math.sqrt(na * nb) : 0;
}

export function similarity(textA, textB) {
  return Math.max(0, Math.min(1, cosine(embed(textA), embed(textB))));
}
