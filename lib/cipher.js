// RE of the site's request-signing cipher:
// three CBC-ish S-box rounds over [0,255] bytes. S-boxes/keys come from
// material.json (captured at runtime from the live bundle).
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const MATERIAL_PATH = process.env.COMIX_MATERIAL || path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'material.json');

let material = null;

export function loadMaterial() {
  if (material) return material;
  material = JSON.parse(fs.readFileSync(MATERIAL_PATH, 'utf8'));
  if (material.sboxes?.length !== 3 || material.keys?.length !== 3) {
    throw new Error('invalid material.json');
  }
  return material;
}

export function reloadMaterial() {
  material = null;
  return loadMaterial();
}

const HEX = '0123456789ABCDEF';

export function encodeURIComponent(value) {
  let out = '';
  for (const b of Buffer.from(value, 'utf8')) {
    const c = b & 0xff;
    if (
      (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) || (c >= 0x30 && c <= 0x39) ||
      c === 0x2d || c === 0x5f || c === 0x2e || c === 0x21 || c === 0x7e ||
      c === 0x2a || c === 0x27 || c === 0x28 || c === 0x29
    ) {
      out += String.fromCharCode(c);
    } else {
      out += '%' + HEX[(c >> 4) & 0xf] + HEX[c & 0xf];
    }
  }
  return out;
}

// Builds the canonical, sorted, indexed query string
export function canonicalizes(params) {
  const parts = [];
  for (const key of Object.keys(params).sort()) {
    const entry = params[key];
    if (entry.length === 1) {
      parts.push(`${key}=${encodeURIComponent(entry[0])}`);
    } else {
      entry.forEach((v, i) => parts.push(`${key}[${i}]=${encodeURIComponent(v)}`));
    }
  }
  return parts.join('&');
}

function b64url(data) {
  return Buffer.from(data).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlDecode(s) {
  const fixed = s.replace(/-/g, '+').replace(/_/g, '/');
  const padded = fixed + '='.repeat((4 - (fixed.length % 4)) % 4);
  return Buffer.from(padded, 'base64');
}

const PREVES = [189, 133, 32];

function subRound(data, sbox, key, prev) {
  const out = Buffer.alloc(data.length);
  let p = prev;
  for (let i = 0; i < data.length; i++) {
    const idx = (data[i] ^ key[i % key.length] ^ p) & 0xff;
    const v = sbox[idx];
    out[i] = v;
    p = v;
  }
  return out;
}

function subRoundInv(data, sbox, key, prev) {
  const inv = new Int32Array(256);
  for (let i = 0; i < 256; i++) inv[sbox[i] & 0xff] = i;
  const out = Buffer.alloc(data.length);
  let p = prev;
  for (let i = 0; i < data.length; i++) {
    const b = data[i] & 0xff;
    const idx = inv[b];
    out[i] = (idx ^ key[i % key.length] ^ p) & 0xff;
    p = b;
  }
  return out;
}

// Mints the `_` token for a path (may include /api/v1 prefix) with an
// optional pre-canonicalized query string
export function generateUnderscore(fullPath, query) {
  const r0Path = fullPath.replace(/^\/api\/v1/, '');
  const mat = loadMaterial();
  const input = query ? `${r0Path}?${query}` : r0Path;
  let data = Buffer.from(input, 'utf8');
  for (let round = 0; round < 3; round++) {
    data = subRound(data, mat.sboxes[round], mat.keys[round], PREVES[round]);
  }
  return b64url(data);
}

export function decryptE(e) {
  const mat = loadMaterial();
  const raw = b64urlDecode(e);
  const step2 = subRoundInv(raw, mat.sboxes[2], mat.keys[2], PREVES[2]);
  const step1 = subRoundInv(step2, mat.sboxes[1], mat.keys[1], PREVES[1]);
  return subRoundInv(step1, mat.sboxes[0], mat.keys[0], PREVES[0]);
}
