// comix.to request signer - pure Node, no browser.
//
// Recovered by tracing the site's bytecode VM. See ALGORITHM.md for the derivation.
//
//   sign(path, params) -> "pgr.<16 base64url chars>"
//
// Structure:
//   1. canonicalise   - flatten/sort the query, strip /api/v1
//   2. words          - big-endian uint32, final partial word padded 0x80 then zeros
//   3. pass A         - the feedback mixer over the request's words
//   4. pass B         - the same mixer over the expansion seeds
//   5. lanes          - 8 output words
//   6. pack           - base64url of the lanes as BE 4-byte words, first 16 chars

import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);

const rotr = (v, n) => ((v >>> n) | (v << (32 - n))) >>> 0;
const f = (x) => ((rotr(x, 7) ^ rotr(x, 18)) ^ (x >>> 3)) >>> 0;
const g = (x) => ((rotr(x, 17) ^ rotr(x, 19)) ^ (x >>> 10)) >>> 0;

// ---------------------------------------------------------------- 1. canonicalise

function flatten(params, prefix, out) {
  for (const [name, value] of Object.entries(params)) {
    const key = prefix ? `${prefix}[${name}]` : name;
    if (Array.isArray(value)) value.forEach((v, i) => out.push([`${key}[${i}]`, v]));
    else if (value && typeof value === 'object') flatten(value, key, out);
    else out.push([key, value]);
  }
  return out;
}

export function canonicalise(path, params) {
  const trimmed = path.replace(/^\/api\/v1/, '');
  const pairs = flatten(params ?? {}, '', [])
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  const qs = pairs.map(([k, v]) => `${k}=${v}`).join('&');
  return qs ? `${trimmed}?${qs}` : trimmed;
}

// ---------------------------------------------------------------- 2. word stream

export function words(canonical) {
  const buf = Buffer.from(canonical, 'latin1');
  const padded = Buffer.alloc(Math.ceil(buf.length / 4) * 4);
  buf.copy(padded);
  padded[buf.length] = 0x80;
  const W = [];
  for (let i = 0; i + 3 < padded.length; i += 4) {
    W.push(((padded[i] << 24) + (padded[i + 1] << 16) + (padded[i + 2] << 8) + padded[i + 3]) >>> 0);
  }
  return W;
}

// ---------------------------------------------------------------- 3/4. the mixer

export const PASS_A = 48;
export const PASS_B = 82;
export const FEEDBACK_LAG = 16;

/**
 * Run the feedback mixer. `S` supplies the stream; `blocks` pins fixed regions (the
 * expansion pass feeds the eight chain seeds, the 0x80 padding and the following zeros
 * in place of the feedback).
 */
export function mix(seed, n, blocks = new Map()) {
  const S = new Array(n + FEEDBACK_LAG).fill(0);
  for (let i = 0; i < Math.min(n, seed.length); i++) S[i] = seed[i];
  for (const [i, v] of blocks) S[i] = v;
  const get = (i) => (i < 0 || i >= S.length ? 0 : S[i]);

  const key = new Array(n), p = new Array(n), acc = new Array(n), inp = new Array(n), q = new Array(n);
  for (let i = 0; i < n; i++) {
    key[i] = f(get(i + 1));
    inp[i] = g(get(i + 14));
    p[i] = (get(i) + key[i]) >>> 0;
    acc[i] = (p[i] + get(i + 9)) >>> 0;
    q[i] = (acc[i] + inp[i]) >>> 0;
    if (i + FEEDBACK_LAG < S.length && !blocks.has(i + FEEDBACK_LAG)) {
      S[i + FEEDBACK_LAG] = q[i];
    }
  }
  return { q, key, p, acc, inp };
}

/** Pass A: the canonical's own words, then the q feedback. */
export function mixCanonical(W) {
  const seed = [...W, 0];
  return mix(seed, PASS_A);
}

// ---------------------------------------------------------------- 5. expansion chains

export const CHAIN_LEN = 192;
const INJECT_FROM = 64;
const INJECT_EVERY = 64;

/** The eight lane addends: s23[191-k] for k<4, s22[195-k] for k>=4. */
export function laneAddends(chains, material) {
  const { C20, C21, C22, C23, inject22, inject20 } = chains;
  const s22 = new Array(CHAIN_LEN).fill(0);
  const s23 = new Array(CHAIN_LEN).fill(0);
  const s20 = new Array(CHAIN_LEN).fill(0);
  const s21 = new Array(CHAIN_LEN).fill(0);
  for (let i = 0; i < CHAIN_LEN; i++) {
    s23[i] = (C22[i] + C23[i]) >>> 0;
    const x22 = inject22.has(i) ? inject22.get(i)
      : (i < 4 ? material[3 - i] >>> 0 : s23[i - 4]);
    s22[i] = (x22 + C22[i]) >>> 0;
    const x20 = inject20.has(i) ? inject20.get(i)
      : (i < 4 ? material[7 - i] >>> 0 : s22[i - 4]);
    s20[i] = (x20 + C20[i]) >>> 0;
    s21[i] = (s20[i] + C21[i]) >>> 0;
  }
  const addends = [];
  for (let k = 0; k < 4; k++) addends.push(s23[CHAIN_LEN - 1 - k] >>> 0);
  for (let k = 4; k < 8; k++) addends.push(s22[CHAIN_LEN + 3 - k] >>> 0);
  return { addends, s20, s21, s22, s23 };
}

/** Extract the chain constants and injection blocks from a captured cipher trace. */
export function chainsFromTrace(events, ops) {
  const bySlot = new Map();
  for (const e of events) if ([15, 16, 17, 18].includes(e[5])) bySlot.set(e[0], (bySlot.get(e[0]) || 0) + 1);
  let cipher = -1, best = 0;
  for (const [id, n] of bySlot) if (n > best) { best = n; cipher = id; }
  const c = events.filter((e) => e[0] === cipher);
  const adds = (s) => c.filter((e) => e[5] === s && ops[e[1]] === '+');
  const s20 = adds(20), s21 = adds(21), s22 = adds(22), s23 = adds(23);
  const inject22 = new Map(), inject20 = new Map();
  for (let i = INJECT_FROM; i < CHAIN_LEN; i += INJECT_EVERY) {
    for (let k = 0; k < 4; k++) { inject22.set(i + k, s22[i + k][2] >>> 0); inject20.set(i + k, s20[i + k][2] >>> 0); }
  }
  return {
    C20: s20.map((e) => e[3] >>> 0), C21: s21.map((e) => e[3] >>> 0),
    C22: s22.map((e) => e[3] >>> 0), C23: s23.map((e) => e[3] >>> 0),
    inject22, inject20,
  };
}

// ---------------------------------------------------------------- 6. output

const B64U = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

export function base64url(bytes) {
  let out = '', bits = 0, val = 0;
  for (const b of bytes) {
    val = (val << 8) | b;
    bits += 8;
    while (bits >= 6) { out += B64U[(val >>> (bits - 6)) & 63]; bits -= 6; }
  }
  if (bits > 0) out += B64U[(val << (6 - bits)) & 63];
  return out;
}

/** Eight lanes, each a big-endian 4-byte word -> 32 bytes -> first 16 base64url chars. */
export function pack(lanes) {
  const bytes = [];
  for (const v of lanes) bytes.push((v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255);
  return base64url(bytes).slice(0, 16);
}

// ---------------------------------------------------------------- sign

/**
 * @param {string} path    e.g. "/api/v1/manga/l9vj2/chapters"
 * @param {object} params  e.g. { limit: 100, order: { number: 'desc' }, page: 1 }
 * @param {object} keys    { kid, material, seedConsts, chains }
 */
export function sign(path, params, keys) {
  const canonical = canonicalise(path, params);
  const W = words(canonical);
  const a = mixCanonical(W);

  const seeds = keys.material.slice(0, 8).map((w, k) =>
    ((((w + keys.seedConsts[k][0]) >>> 0) + keys.seedConsts[k][1]) >>> 0));

  const blocks = new Map();
  for (let k = 0; k < 8; k++) blocks.set(34 + k, seeds[k]);
  blocks.set(42, 0x80000000);
  const b = mix(new Array(16).fill(0), PASS_B, blocks);

  const { addends } = laneAddends(keys.chains, keys.material);
  const lanes = addends.map((m, k) => (keys.laneConsts[k] + m) >>> 0);
  return `${keys.kid}.${pack(lanes)}`;
}

export default { sign, canonicalise, words, mix, mixCanonical, pack, base64url };