// Stage-by-stage validation of lib/signer.js.
//
// Stages 1-5 assert against values captured from a live trace of the site's own code.
// Stage 6 is the end-to-end sign() and is expected to fail until the lane addends are
// derived rather than supplied.

import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { sign, canonicalise, words, mixCanonical, pack, base64url, laneAddends, chainsFromTrace } from './lib/signer.js';

const here = dirname(fileURLToPath(import.meta.url));
const scratch = process.env.SCRATCH || join(here, '..', 'extensions-source', '.scratch', 'comix-re');
const material = fs.readFileSync(join(scratch, 'material.bin'));
const MW = [];
for (let i = 0; i + 3 < material.length; i += 4) {
  MW.push(((material[i] << 24) + (material[i + 1] << 16) + (material[i + 2] << 8) + material[i + 3]) >>> 0);
}

let failures = 0;
const check = (label, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  if (!ok) failures++;
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${label}`);
  if (!ok) console.log(`          got  ${JSON.stringify(got)}\n          want ${JSON.stringify(want)}`);
};

const CASES = [
  ['/api/v1/manga/l9vj2/chapters', { limit: 100, order: { number: 'desc' }, page: 1 }, 'pgr.SXB3RfysEnulZoxO'],
  ['/api/v1/manga', { order: { chapter_updated_at: 'desc' }, page: 1, limit: 28, content_rating: ['safe', 'suggestive'] }, 'pgr.KjBH_rQkBBNYtbkK'],
  ['/api/v1/manga', { order: { relevance: 'desc' }, page: 1, limit: 28, content_rating: ['safe', 'suggestive'], keyword: 'demon overrun' }, 'pgr.KHyT67D-VXo30fKt'],
];

console.log('=== stage 1: canonicalise ===');
check('chapter list', canonicalise(CASES[0][0], CASES[0][1]), '/manga/l9vj2/chapters?limit=100&order[number]=desc&page=1');
check('browse list', canonicalise(CASES[1][0], CASES[1][1]), '/manga?content_rating[0]=safe&content_rating[1]=suggestive&limit=28&order[chapter_updated_at]=desc&page=1');
check('search', canonicalise(CASES[2][0], CASES[2][1]), '/manga?content_rating[0]=safe&content_rating[1]=suggestive&keyword=demon overrun&limit=28&order[relevance]=desc&page=1');

console.log('\n=== stage 2: word stream ===');
const W = words('/manga/l9vj2/chapters?limit=100&order[number]=desc&page=1');
check('word count', W.length, 15);
check('word 0', W[0] >>> 0, 0x2f6d616e);
check('word 14 padded', W[14] >>> 0, 0x31800000);

console.log('\n=== stage 3: base64url + lane packing ===');
check('base64url("Man")', base64url(Buffer.from('Man')), 'TWFu');
const lanes = [0x49707745, 0xfcac127b, 0xa5668c4e, 0xa9ed7f4c, 0x5cfbb0ac, 0x84353663, 0x2fa5543c, 0xf9cd5afa];
check('pack reproduces the traced token body', pack(lanes), 'SXB3RfysEnulZoxO');

console.log('\n=== stage 4: the mixer (pass A, 48 iterations) ===');
const OPS = ["&","<=","%",">","==",">>","+","!=",">=","<","/","**","|","!","^","*","===","<<",">>>","-"];
const E = JSON.parse(fs.readFileSync(join(scratch, 'loop14.json'), 'utf8'));
const cipher = E.filter((e) => e[0] === 87);
const a16 = cipher.filter((e) => e[5] === 16 && OPS[e[1]] === '+');
const a18 = cipher.filter((e) => e[5] === 18 && OPS[e[1]] === '+');
const m = mixCanonical(W);
const rows = [
  ['key', m.key, a16.slice(0, 48).map((e) => e[3] >>> 0)],
  ['p', m.p, a16.slice(0, 48).map((e) => e[4] >>> 0)],
  ['acc', m.acc, a18.slice(0, 48).map((e) => e[2] >>> 0)],
  ['inp', m.inp, a18.slice(0, 48).map((e) => e[3] >>> 0)],
  ['q', m.q, a18.slice(0, 48).map((e) => e[4] >>> 0)],
];
for (const [name, got, want] of rows) {
  let ok = 0;
  for (let i = 0; i < 48; i++) if ((got[i] >>> 0) === (want[i] >>> 0)) ok++;
  if (ok !== 48) failures++;
  console.log(`  ${ok === 48 ? 'PASS' : 'FAIL'}  ${name.padEnd(4)} ${ok}/48`);
}

console.log('\n=== stage 5: material ===');
check('material is 1088 bytes / 272 words', MW.length, 272);
check('material word 0', MW[0] >>> 0, 0xebef80d9);

console.log('\n=== stage 6: expansion seeds ===');
// seed[k] = (material[k] + c1) + c2, extracted from the chain ops
const SEED_CONSTS = [
  [0xdb8e7a01, 0x96b7d2b0], [0x32c057fa, 0xc5f405b9], [0x82cc05bf, 0xcd6b441b],
  [0xa54b061d, 0x3a6b01ff], [0x5a4f7662, 0x09e26df2], [0x4e4aa640, 0x1a15f627],
  [0x427b7654, 0x057a1bf0], [0x1988e6e8, 0xf41c9851],
];
check('seeds from material + 16 constants',
  MW.slice(0, 8).map((w, k) => ((((w + SEED_CONSTS[k][0]) >>> 0) + SEED_CONSTS[k][1]) >>> 0)),
  [0x5e35cd8a, 0xde6fec88, 0x85d65798, 0x75592696, 0x65c211d5, 0x5ea2f44d, 0x9091aa35, 0x28cb5a37]);

console.log('\n=== stage 7: expansion chains ===');
const chains = chainsFromTrace(E, OPS);
const { addends, s20, s21, s22, s23 } = laneAddends(chains, MW);
const tracedAdds = (s) => cipher.filter((e) => e[5] === s && OPS[e[1]] === '+').map((e) => e[4] >>> 0);
for (const [nm, v, slot] of [['s20', s20, 20], ['s21', s21, 21], ['s22', s22, 22], ['s23', s23, 23]]) {
  const tr = tracedAdds(slot);
  let ok = 0;
  for (let i = 0; i < 192; i++) if ((v[i] >>> 0) === (tr[i] >>> 0)) ok++;
  if (ok !== 192) failures++;
  console.log(`  ${ok === 192 ? 'PASS' : 'FAIL'}  ${nm} reproduces the chain  ${ok}/192`);
}
check('the eight lane addends', addends,
  [0x665c3458, 0x5f3a988d, 0xb4501b5f, 0xeaa5e339, 0x2c4e5966, 0xaedcb73a, 0x80ab0031, 0x09bcdc24]);

console.log('\n=== stage 8: end-to-end sign() ===');
// The lane addends are LANE_CONSTS + addend[k]. LANE_CONSTS is fixed per build;
// the addends above are the ones for this request.
const keys = {
  kid: 'pgr',
  material: MW,
  seedConsts: SEED_CONSTS,
  chains,
  laneConsts: [0xe31442ed, 0x9d7179ee, 0xf11670ef, 0xbf479c13, 0x30ad5746, 0xd5587f29, 0xaefa540b, 0xf0107ed6],
};
check('sign() chapter list', sign(CASES[0][0], CASES[0][1], keys), CASES[0][2]);

console.log('\n  ....  the chain constants C20..C23 are request-derived (measured: they agree');
console.log('  ....  with a previous request for ~14 entries, then diverge where the');
console.log('  ....  canonical ends). sign() therefore reproduces the token it is given chain');
console.log('  ....  constants for, but cannot yet derive them from the material alone.');

console.log(`\n${failures} failure(s)`);
process.exit(failures ? 1 : 0);