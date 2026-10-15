// Answers the site's click-the-shapes captcha, ported from the extension's
// ShapesSolver (which itself came from assets/solve_captcha.js).
//
// The picture carries flat palette-coloured shapes with a dark shadow beside each;
// the strip carries the same shapes to be found. Every shape is matched against the
// go-captcha stock set by normalising both to an area- and centroid-aligned
// GRID x GRID mask and taking the best intersection-over-union over every candidate
// rotation, then the strip shapes are assigned to picture shapes greedily-optimal and
// the margin of the best assignment over the runner-up is returned, so a caller can
// ask for a fresh challenge when the picture is too ambiguous to answer confidently.
import { PNG } from 'pngjs';

const GRID = 40;
const SHAPE_SIZE = 60;
const CONFIDENT_MARGIN = 2.2;
const SIZES = Array.from({ length: 19 }, (_, i) => 18 + i);
const ANGLES = Array.from({ length: 120 }, (_, i) => i * 3)
  .filter((a) => (a >= 15 && a <= 75) || (a >= 285 && a <= 345));
const MASTER_PALETTE = ['#fde98e', '#60c1ff', '#fcb08e', '#fb88ff', '#b4fed4', '#cbfaa9', '#78d6f8'];
const THUMB_PALETTE = ['#1f55c4', '#780592', '#2f6b00', '#910000', '#864401', '#675901', '#016e5c'];

// go-captcha's stock shape set (https://github.com/wenlng/go-captcha-assets, Apache-2.0),
// each a 60x60 one-bit-per-pixel bitmap.
const SHAPE_ASSETS = ["AAAAAH4AAAAAAAAf8AAAAAAAA/+AAAAAAAB//AAAAAAAB//gAAAAAAB//gAAAA8AB//wAAAB+AD//wAAAD/gD//+AAAH/gD///wAAH/wD///8AAP/4D///+AAP/8H////AAP/+H////AAP/+H////AAP//H////AAf//n////AB///3///+AH///3///8AP///////wAf///////gA///////+AA///////4AA///////wAA////////wAf////////8f////////+P////////+H/////////A/////////AB////////AAAf//////AAA//////+AAB//////8AAH//////4AAP//////wAAf//////gAB//////+AAD//////8AAH//////8AAP//////8AAf//////8AAf///9//8AAf///9//8AA////87/8AAf///85/4AAf///48/4AAP///48fwAAD///48HAAAAA//4+AAAAAA//w+AAAAAAf/w+AAAAAAf/w+AAAAAAP/h+AAAAAAH/B+AAAAAAD8B4AAAAAAAADwAAAAAAAADAAAAAAAAACAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAH8AAAAAAAAP+AAAAAAAAf/AAAAAAAB//gAAAAAAH//4AAAAAf/////AAAB//////gAAB//////wAAD//////wAAD//////4AAD//////4AAD//////4AAD//////4AAH//////4AAH//////4AAH//////8AAP//////+AAf///////AB////////gD////////wH////////4H////////8P////////8P////////8P////////8P////////8H////////8D////////4D////////wB////////wB////////gA////////gA////////gA////////gA////////gA////////gB////////gB////////gB////////wB////////wB////////gB////////gA////////AAf//////+AAH//////8AAA//////AAAAP////8AAAAH////4AAAAD////4AAAAD////wAAAAB////wAAAAB////gAAAAA//f/gAAAAAf4D/AAAAAAHAAcAAAAAAAAAAAAAAAAAAAAAAA", "P+AAAAAAf8f+AAAAAAf+//AAAAAA////////////////////////////////////////////////////////////////AAAAAA///+AAAAAAf/P8AAAAAAP8H4AAAAAAH4H4AAAAAAH4H4AAAAAAH4H4AAAAAAH4H4AAAAAAH4H4AAAAAAH4H4AAAAAAH4H4AAAAAAH4H4AAAAAAH4H4AAAAAAH4H4AAAAAAH4H4AAAAAAH4H4AAAAAAH4H4AAAAAAH4H4AAAAAAH4H4AAAAAAH4H4AAAAAAH4H4AAAAAAH4H4AAAAAAH4H4AAAAAAH4H4AAAAAAH4H4AAAAAAH4H4AAAAAAH4H4AAAAAAH4H4AAAAAAH4H4AAAAAAH4H4AAAAAAH4H4AAAAAAH4H4AAAAAAH4H4AAAAAAH4H4AAAAAAH4H4AAAAAAH4H4AAAAAAH4H4AAAAAAH4H4AAAAAAH4H4AAAAAAH4P8AAAAAAf+/+AAAAAA////AAAAAA////////////////////////////////////////////////////////////////AAAAAA//f+AAAAAA//P+AAAAAAf+", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAH//////8AAf//////+AAf///////AA////////AA////////gA////////gA////////gA////////gA////////gA////////gA////////gA////////gA////////gA////////gA////////gA////////gA////////gA////////gA////////gA////////gA////////gA////////gA////////gA////////gA////////gA////////gA////////gA////////gA////////gA////////gA////////gA////////gA////////gA////////gA////////gA////////gA////////gA////////gA////////gA////////gA////////gA////////gA////////gA////////gA////////gA////////AAf///////AAP//////+AAD//////4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAACAAAAAf/gB/+AAAB//4H//gAAH//+f//4AAP//////8AAf//////+AA////////AB////////gD////////wD////////wH////////4H////////4P////////8P////////8P////////8P////////8P////////8P////////8P////////8P////////8P////////8P////////8P////////8P////////8H////////4H////////4D////////wD////////wB////////gA////////AAf//////+AAP//////8AAH//////4AAD//////wAAB//////gAAA//////AAAAf////+AAAAP////8AAAAH////4AAAAD////wAAAAB////gAAAAA////AAAAAAf//+AAAAAAP//8AAAAAAH//4AAAAAAD//wAAAAAAB//gAAAAAAA//AAAAAAAAf+AAAAAAAAP8AAAAAAAAH4AAAAAAAADwAAAAAAAABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "AAAAH4AAAAAAAAf+AAAAAAAA//AAAAAAAA//AAAAAAAB//gAAAAAAB//gAAAAAAB//gAAAAD/D//w/wAAH/n//5/4AAP//////8AAf//////+AAf//////+AAf/8//P/+AAf/8P+P/+AAf/8H4P/+AAf/4AAH/+AAf/4AAH/+AAf/4AAH/+AAP/wAAD/8AAH/gAAB/4AAH/AAAA/4AAP4AAAAH8AAfAAAAAA+AD/AAAAAA/wP/gAAAAB/8f/wAAAAB/+f/wAAAAD/+//4AAAAH////4AAAAH////4AAAAH////4AAAAH////4AAAAH////4AAAAH//f/wAAAAD/+f/gAAAAB/+P/gAAAAB/8D/AAAAAA/wAfAAAAAA+AAP4AAAAH8AAH/AAAA/4AAH/gAAB/4AAP/wAAD/8AAf/4AAH/+AAf/4AAH/+AAf/4AAH/+AAf/8H4P/+AAf/8f8P/+AAf/8//P/+AAf//////+AAf//////8AAP//////8AAH/n//5/4AAD/D//w/gAAAAB//gAAAAAAB//gAAAAAAB//gAAAAAAA//AAAAAAAA//AAAAAAAAP8AAAAAAAAH4AAAA", "AAAAAAAAAAAAAABgAAAAAAAAP8AAAAAAAAf+AAAAAAAA//AAAAAAAB//gAAAAAAB//gAAAAAAD//wAAAAAAD//wAAAAAAD//wAAAAAAH//4AAAAAAH//4AAAAAAH//4AAAAAAH//4AAAAAAH//4AAAAAAH//4AAAAAAH//4AAAAf8H//4P+AB//v/////gD////////wH////////4P////////8P////////8f////////+f////////+f////////+P////////8P////////8P////////8H////////4D////////wD////////wB////////gAf//////+AAP//////8AAD//////wAAAf////+AAAAH////4AAAAP////8AAAAf////+AAAAf////+AAAA//////AAAB//////gAAB//////gAAB//////gAAD//////wAAD//////wAAD//////wAAD//////wAAD//+f//wAAD//+f//wAAD//8P//wAAD//4H//wAAD//wD//wAAD//gB//wAAB//AA//gAAA/+AAf/AAAAf4AAH+AAAAAAAAAAAAAAAAAAAAAA", "AAAAAAPgAAAAD8AB/gAAAAH/gD/wAAAAH/wP/4AAAAP/8P/4AAAAP/+P/8AAAAf//H/8AAAAf//j/8AAAAf//j/8AAAA///x/+AAAA///x/+AAAA///5/+AAAAD//5/+AAAAAf/5/+AAAAAH/9/+AAAP/h/8/8OAA//4/8H8fgD//wH8A8fwH//gB4AYf8P//AAwAI/+f/+AAAAA////+AAAAB////8AAAAD////8AAAAD//f/8AAAAD/+f/8AAAAD/+P/gAAAAD/8P+AAAAAD/8H8OAAAAH/4DweAAAAH/wBh+AAAAH/gAD/AAAAP/AAH/gAAAf+AAH/gAAAf4AAP/wAAA/gAAf/wAAAAAAAf/wAAAAPAA//mAAP//AA//nAAf//AA//HgA///gA//P4D///gB//P8H///gB//P/H///gB/+P/H///gB/+P/j///gA/+P/x///gA/+P/wf//gA//P/4P//AAf/P/8D/8AAD+H/+AHAAAAAH//gAAAAAAH//wAAAAAAD//wAAAAAAB//wAAAAAAB//gAAAAAAA//AAAAAAAAf+AAAAAAAAP8AAAAAAAAH4AAAAAAAABgAAAA", "AAAA//AAAAAAAH//4AAAAAA////AAAAAD////wAAAAP////8AAAAf////+AAAB//////gAAD//////wAAH//////4AAP//////8AAf//////+AA////////AA///wD///AB//+AAf//gD//4AAH//wD//gAAB//wH//AAAA//4H/+AAAAf/4P/8AAAAP/8P/4AAAAH/8P/4AAAAH/8f/wAAAAD/+f/wAAAAD/+f/gAAAAB/+//gAAAAB////gAAAAB////AAAAAA////AAAAAA////AAAAAA////AAAAAA////AAAAAA////AAAAAA////AAAAAA////AAAAAA////gAAAAB////gAAAAB//f/gAAAAB/+f/wAAAAD/+f/wAAAAD/+P/4AAAAH/8P/4AAAAH/8P/8AAAAP/8H/+AAAAf/4H//AAAA//4D//gAAB//wD//4AAH//wB//+AAf//gA///wD///AA////////AAf//////+AAP//////8AAH//////4AAD//////wAAB//////gAAAf////+AAAAP////8AAAAD////wAAAAA////AAAAAAH//4AAAAAAA//AAAA", "AAAAAAAAAAAAAAAAAAAAAAwAAAAEAAAB+AAAB+AAAD/gAAH/AAAD/4DAf/AAAD/8Hg//AAAD/+Px//AAAD/8f4//AAAD/8f8//AAAD/4/8f/AAAB/5/+f+AAAB/x/+P+AAAB/x/+P+AAAB/j//H+AAAAAB//AAAAAAAA//AAAAAAP4P/HwAAAD/+H/P/AAAH//D+P/gAAP//h+P/wAAP//wOf/wAAP//gAf/wAAH//AA//gAAH/+AA//gAAD/+AB//AAAB/wAA/+AAAY/gAA/8IAA8eAAB/48AB+MOAB/h+AD/AeAB/D/AH/g/AAAH/gP/x/gAAP/wf/z/gf+P/4//j/j//H/4//j/z//H/8//n/z//n/8f/n/z//n/4P/n/x//j/wA/H/5//j8AAAH/4//gAAAAH/4f/gAAAAH/wP/gAAAAH/AD/gAAAAH8Hg/gAAAADgf4HAAAAAAB/+AAAAAAAD//AAAAAAAD//AAAAAAAB/+AAAAAAAB/+AAAAAAAA/8AAAAAAAA/8AAAAAAAAf4AAAAAAAAf4AAAAAAAAPwAAAAAAAAHgAAAAAAAADAAAAAAAAAAAAAAAAAAAAAAAAA", "AAAAH4AAAAAAAAf+AAAAAAAA//AAAAAAAA//AAAAAAAB//gAAAAAAB//gAAAAAAB//gAAAAB+D//w/gAAH/j//x/wAAP//////4AAP//////8AAf//////+AAf//////+AAf//////+AAf//////+AAf//////+AAf//////+AAf//wD//8AAP/+AAf/8AAH/8AAP/4AAH/4AAH/4AAH/wAAD/4AAf/gAAB/+AD//AAAA//wP//AAAA//8f//AAAA//+f/+AAAAf/+//+AAAAf////+AAAAf////+AAAAf////+AAAAf////+AAAAf////+AAAAf//f/+AAAAf/+f//AAAA//+P//AAAA//8D//AAAA//wAf/gAAB/+AAH/wAAD/4AAH/4AAH/4AAH/8AAP/4AAP/+AAf/8AAf//wD//+AAf//////+AAf//////+AAf//////+AAf//////+AAf//////+AAf//////+AAP//////8AAP//////8AAH/j//x/4AAB/B//wfgAAAAB//wAAAAAAB//gAAAAAAB//gAAAAAAA//gAAAAAAAf/AAAAAAAAP+AAAAAAAAH4AAAA", "AAB////gAAAAD////wAAAAH////4AAAAP////8AAAAf////+AAAA//////AAAB//////gAAD//////wAAH//////4AAP//////8AAf//////+AA////////AB////////gD////////wH////////4P////////8f////////+////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////f////////+P////////8H////////4D////////wB////////gA////////AAf//////+AAP//////8AAH//////4AAD//////wAAB//////gAAA//////AAAAf////+AAAAP////8AAAAH////4AAAAD////wAAAAB////gAA", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP8AAAAAAAD//4AAAAAAf//+AAAAAB////gAAAAD////4AAAAP////8AAAAf/////AAAA//////gAAB//////wAAD//////4AAH//////4AAP//////8AAP//////+AAf///////AA////////AA////////gB////////gB////////gB////////wD////////wD////////wD////////4D////////4H////////4H////////4H////////4H////////4H////////4H////////4H////////4H////////4D////////4D////////4D////////4D////////wB////////wB////////wB////////gA////////gA////////AAf///////AAf//////+AAP//////+AAH//////8AAH//////4AAD//////wAAB//////gAAA//////AAAAP////+AAAAH////8AAAAD////wAAAAA////AAAAAAH//8AAAAAAA//gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"];

/** Decodes a base64 data URL into ARGB, so no image library is needed. */
export function decodeImage(dataUrl) {
  const base64 = String(dataUrl || '').split(',').pop();
  const png = PNG.sync.read(Buffer.from(base64, 'base64'));
  const pixels = new Int32Array(png.width * png.height);
  for (let i = 0; i < pixels.length; i++) {
    const o = i * 4;
    // PNG stores straight (not premultiplied) alpha, so the channels are used as they are
    const a = png.data[o + 3];
    const r = png.data[o];
    const g = png.data[o + 1];
    const b = png.data[o + 2];
    pixels[i] = (((a << 24) | (r << 16) | (g << 8) | b) | 0);
  }
  return { width: png.width, height: png.height, pixels };
}

/** JS Math.round: halves go towards positive infinity. */
const jsRound = (v) => Math.floor(v + 0.5);

const palette = (hexes) => hexes.map((h) => [
  parseInt(h.slice(1, 3), 16),
  parseInt(h.slice(3, 5), 16),
  parseInt(h.slice(5, 7), 16),
]);

function nearestColour(pixels, pal) {
  const nearest = new Int32Array(pixels.length);
  const distance = new Float32Array(pixels.length);
  for (let p = 0; p < pixels.length; p++) {
    const colour = pixels[p];
    const r = (colour >> 16) & 0xff;
    const g = (colour >> 8) & 0xff;
    const b = colour & 0xff;
    let best = 0;
    let bestD = Infinity;
    for (let k = 0; k < pal.length; k++) {
      const dr = r - pal[k][0];
      const dg = g - pal[k][1];
      const db = b - pal[k][2];
      const d = dr * dr + dg * dg + db * db;
      if (d < bestD) {
        bestD = d;
        best = k;
      }
    }
    nearest[p] = best;
    distance[p] = Math.sqrt(bestD);
  }
  return [nearest, distance];
}

// ---------- morphology ----------

function dilate(mask, w, h, r) {
  const out = new Uint8Array(w * h);
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      if (!mask[y * w + x]) continue;
      for (let dy = -r; dy <= r; dy++) {
        const ny = y + dy;
        if (ny < 0 || ny >= h) continue;
        for (let dx = -r; dx <= r; dx++) {
          const nx = x + dx;
          if (nx >= 0 && nx < w) out[ny * w + nx] = 1;
        }
      }
    }
  }
  return out;
}

function erode(mask, w, h, r) {
  const inverse = new Uint8Array(mask.length);
  for (let i = 0; i < mask.length; i++) inverse[i] = mask[i] ? 0 : 1;
  const dilated = dilate(inverse, w, h, r);
  const out = new Uint8Array(mask.length);
  for (let i = 0; i < mask.length; i++) out[i] = dilated[i] ? 0 : 1;
  return out;
}

function neighbours(mask, w, h) {
  const out = new Int32Array(w * h);
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      let n = 0;
      for (let dy = -1; dy <= 1; dy++) {
        for (let dx = -1; dx <= 1; dx++) {
          if (dy === 0 && dx === 0) continue;
          const ny = y + dy;
          const nx = x + dx;
          if (ny >= 0 && ny < h && nx >= 0 && nx < w && mask[ny * w + nx]) n++;
        }
      }
      out[y * w + x] = n;
    }
  }
  return out;
}

/** 4-connected components as pixel-index lists. */
function components(mask, w, h) {
  const seen = new Uint8Array(w * h);
  const out = [];
  for (let start = 0; start < mask.length; start++) {
    if (!mask[start] || seen[start]) continue;
    const stack = [start];
    const found = [];
    seen[start] = 1;
    while (stack.length) {
      const p = stack.pop();
      found.push(p);
      const x = p % w;
      const y = (p / w) | 0;
      const around = [[x + 1, y], [x - 1, y], [x, y + 1], [x, y - 1]];
      for (const [nx, ny] of around) {
        if (nx < 0 || nx >= w || ny < 0 || ny >= h) continue;
        const q = ny * w + nx;
        if (mask[q] && !seen[q]) {
          seen[q] = 1;
          stack.push(q);
        }
      }
    }
    out.push(found);
  }
  return out;
}

function bounds(pixels, w) {
  let minX = Infinity;
  let maxX = -1;
  let minY = Infinity;
  let maxY = -1;
  let sumX = 0;
  let sumY = 0;
  for (const p of pixels) {
    const x = p % w;
    const y = (p / w) | 0;
    if (x < minX) minX = x;
    if (x > maxX) maxX = x;
    if (y < minY) minY = y;
    if (y > maxY) maxY = y;
    sumX += x;
    sumY += y;
  }
  return { minX, maxX, minY, maxY, cx: sumX / pixels.length, cy: sumY / pixels.length };
}

/** Area-normalised, centroid-centred GRID x GRID mask sampled back from the source pixels. */
function normalise(pixels, w) {
  const b = bounds(pixels, w);
  const bw = b.maxX - b.minX + 1;
  const bh = b.maxY - b.minY + 1;
  const src = new Uint8Array(bw * bh);
  for (const p of pixels) {
    src[(((p / w) | 0) - b.minY) * bw + (p % w) - b.minX] = 1;
  }
  const scale = Math.sqrt(pixels.length) / (GRID * 0.42);
  const out = new Uint8Array(GRID * GRID);
  for (let gy = 0; gy < GRID; gy++) {
    const sy = Math.floor((gy - GRID / 2 + 0.5) * scale + b.cy - b.minY + 0.5);
    if (sy < 0 || sy >= bh) continue;
    for (let gx = 0; gx < GRID; gx++) {
      const sx = Math.floor((gx - GRID / 2 + 0.5) * scale + b.cx - b.minX + 0.5);
      if (sx >= 0 && sx < bw) out[gy * GRID + gx] = src[sy * bw + sx];
    }
  }
  return out;
}

/** Bridge the noise lines drawn across strip shapes, then drop line and mark pixels. */
function thumbClean(mask, w, h) {
  const closed = erode(dilate(mask, w, h, 1), w, h, 1);
  for (let i = 0; i < mask.length; i++) if (mask[i]) closed[i] = 1;
  const n = neighbours(closed, w, h);
  const out = new Uint8Array(mask.length);
  for (let i = 0; i < mask.length; i++) out[i] = closed[i] && n[i] >= 4 ? 1 : 0;
  return out;
}

// ---------- shape assets ----------

const shapeBits = SHAPE_ASSETS.map((encoded) => {
  const bytes = Buffer.from(encoded, 'base64');
  const bits = new Uint8Array(SHAPE_SIZE * SHAPE_SIZE);
  for (let i = 0; i < bits.length; i++) {
    bits[i] = (bytes[i >> 3] >> (7 - (i & 7))) & 1;
  }
  return bits;
});

const resizedCache = new Map();

/** Shape scaled to (size + 10)^2 the way go-captcha draws it, by averaging 4x4 samples. */
function resize(shape, size) {
  const key = shape * 100 + size;
  const cached = resizedCache.get(key);
  if (cached) return cached;
  const s = size + 10;
  const f = SHAPE_SIZE / s;
  const bits = shapeBits[shape];
  const out = new Uint8Array(s * s);
  let area = 0;
  for (let y = 0; y < s; y++) {
    for (let x = 0; x < s; x++) {
      let sum = 0;
      for (let i = 0; i < 4; i++) {
        for (let j = 0; j < 4; j++) {
          const by = Math.floor((y + (i + 0.5) / 4) * f);
          const bx = Math.floor((x + (j + 0.5) / 4) * f);
          if (bits[by * SHAPE_SIZE + bx]) sum++;
        }
      }
      if (sum > 8) {
        out[y * s + x] = 1;
        area++;
      }
    }
  }
  const result = { side: s, mask: out, area };
  resizedCache.set(key, result);
  return result;
}

const templateCache = new Map();

function template(shape, size, thumb) {
  const key = (shape * 100 + size) * 2 + (thumb ? 1 : 0);
  const cached = templateCache.get(key);
  if (cached) return cached;
  const base = resize(shape, size);
  const side = base.side;
  const pad = 3;
  const out = side + 2 * pad + Math.ceil(side * 0.5);
  const c = (side - 1) / 2;
  const oc = (out - 1) / 2;
  const built = ANGLES.map((angle) => {
    const rad = (angle * Math.PI) / 180;
    const cosA = Math.cos(rad);
    const sinA = Math.sin(rad);
    let rotated = new Uint8Array(out * out);
    for (let y = 0; y < out; y++) {
      for (let x = 0; x < out; x++) {
        const dx = x - oc;
        const dy = y - oc;
        const sx = jsRound(cosA * dx - sinA * dy + c);
        const sy = jsRound(sinA * dx + cosA * dy + c);
        if (sx >= 0 && sx < side && sy >= 0 && sy < side) rotated[y * out + x] = base.mask[sy * side + sx];
      }
    }
    if (thumb) rotated = thumbClean(rotated, out, out);
    const filled = [];
    for (let i = 0; i < rotated.length; i++) if (rotated[i]) filled.push(i);
    return normalise(filled, out);
  });
  templateCache.set(key, built);
  return built;
}

function scores(blob, thumb) {
  const out = new Float64Array(shapeBits.length);
  for (let shape = 0; shape < shapeBits.length; shape++) {
    let bestSize = SIZES[0];
    for (const candidate of SIZES) {
      if (Math.abs(resize(shape, candidate).area - blob.area)
        < Math.abs(resize(shape, bestSize).area - blob.area)) {
        bestSize = candidate;
      }
    }
    let best = 0;
    for (const candidate of template(shape, bestSize, thumb)) {
      let inter = 0;
      let union = 0;
      for (let i = 0; i < candidate.length; i++) {
        if (candidate[i] && blob.mask[i]) inter++;
        if (candidate[i] || blob.mask[i]) union++;
      }
      if (union > 0) best = Math.max(best, inter / union);
    }
    out[shape] = best;
  }
  return out;
}

function softmax(values) {
  let max = -Infinity;
  for (const v of values) if (v > max) max = v;
  const exps = new Float64Array(values.length);
  let sum = 0;
  for (let i = 0; i < values.length; i++) {
    exps[i] = Math.exp((values[i] - max) / 0.01);
    sum += exps[i];
  }
  const out = new Float64Array(exps.length);
  for (let i = 0; i < exps.length; i++) out[i] = exps[i] / sum;
  return out;
}

// ---------- blob extraction ----------

function masterBlobs(bitmap) {
  const w = bitmap.width;
  const h = bitmap.height;
  const data = bitmap.pixels;
  const pal = palette(MASTER_PALETTE);
  const [nearest, distance] = nearestColour(data, pal);
  const dark = new Uint8Array(w * h);
  for (let i = 0; i < w * h; i++) {
    const c = data[i];
    dark[i] = ((c >> 16) & 0xff) + (((c >> 8) & 0xff) + (c & 0xff)) < 150 ? 1 : 0;
  }

  const tooBig = (pixels) => {
    const b = bounds(pixels, w);
    return pixels.length > 1400 || b.maxY - b.minY >= 60 || b.maxX - b.minX >= 60;
  };

  const pieces = (pixels, group, found) => {
    const sub = new Uint8Array(w * h);
    for (const p of pixels) sub[p] = 1;
    const grouped = group > 0 ? dilate(sub, w, h, group) : sub;
    for (const joined of components(grouped, w, h)) {
      const own = [];
      for (const q of joined) if (sub[q]) own.push(q);
      if (!own.length) continue;
      if (group > 0 && tooBig(own)) pieces(own, group - 1, found);
      else found.push(own);
    }
    return found;
  };

  const blobs = [];
  for (let k = 0; k < pal.length; k++) {
    const pixels = [];
    for (let p = 0; p < w * h; p++) if (nearest[p] === k && distance[p] < 40) pixels.push(p);
    for (const blob of pieces(pixels, 2, [])) {
      const b = bounds(blob, w);
      const bh = b.maxY - b.minY + 1;
      const bw = b.maxX - b.minX + 1;
      if (blob.length < 120 || blob.length > 1400 || bh < 14 || bh > 60 || bw < 14 || bw > 60) continue;
      const own = new Uint8Array(w * h);
      for (const p of blob) own[p] = 1;
      const ring = dilate(own, w, h, 2);
      let shadow = 0;
      for (let p = 0; p < w * h; p++) if (ring[p] && !own[p] && dark[p]) shadow++;
      let meanDistance = 0;
      for (const p of blob) meanDistance += distance[p];
      meanDistance /= blob.length;
      if (shadow < 3 || meanDistance > 20) continue;
      blobs.push({ x: jsRound(b.cx), y: jsRound(b.cy), area: blob.length, mask: normalise(blob, w) });
    }
  }
  return blobs;
}

function thumbBlobs(bitmap, count) {
  const w = bitmap.width;
  const h = bitmap.height;
  const data = bitmap.pixels;
  const pal = palette(THUMB_PALETTE);
  const [nearest, distance] = nearestColour(data, pal);
  const found = [];
  for (let k = 0; k < pal.length; k++) {
    const mask = new Uint8Array(w * h);
    for (let i = 0; i < w * h; i++) {
      mask[i] = (data[i] >>> 24) > 128 && distance[i] < 60 && nearest[i] === k ? 1 : 0;
    }
    for (const c of components(thumbClean(mask, w, h), w, h)) found.push(c);
  }
  return found
    .sort((a, b) => b.length - a.length)
    .slice(0, count)
    .sort((a, b) => bounds(a, w).cx - bounds(b, w).cx)
    .map((pixels) => {
      const own = new Uint8Array(w * h);
      for (const p of pixels) own[p] = 1;
      const opened = dilate(erode(own, w, h, 1), w, h, 1);
      const kept = pixels.filter((p) => opened[p]);
      const shape = kept.length >= 0.6 * pixels.length ? kept : pixels;
      return { x: 0, y: 0, area: shape.length, mask: normalise(shape, w) };
    });
}

/**
 * Returns the resolved dots for the challenge plus how far the best assignment beats the
 * runner-up, or null when the strip or picture yields too few shapes to answer.
 */
export function solve(image, thumb, count) {
  const masters = masterBlobs(image);
  const thumbs = thumbBlobs(thumb, count);
  if (thumbs.length < count || masters.length < thumbs.length) return null;

  const masterScores = masters.map((m) => softmax(scores(m, false)));
  const thumbScores = thumbs.map((t) => softmax(scores(t, true)));
  const similarity = thumbScores.map((t) => masterScores.map((m) => {
    let dot = 0;
    for (let i = 0; i < t.length; i++) dot += t[i] * m[i];
    return Math.log(dot + 1e-12);
  }));

  let bestTotal = -Infinity;
  let second = -Infinity;
  let bestPicks = [];
  const picks = new Array(thumbs.length).fill(0);
  const used = new Uint8Array(masters.length);

  const search = (i, total) => {
    if (i === thumbs.length) {
      if (total > bestTotal) {
        second = bestTotal;
        bestTotal = total;
        bestPicks = picks.slice();
      } else if (total > second) {
        second = total;
      }
      return;
    }
    for (let j = 0; j < masters.length; j++) {
      if (used[j]) continue;
      used[j] = 1;
      picks[i] = j;
      search(i + 1, total + similarity[i][j]);
      used[j] = 0;
    }
  };
  search(0, 0);

  if (!bestPicks.length) return null;
  const dots = bestPicks.flatMap((j) => [masters[j].x, masters[j].y]).join(',');
  return { dots, margin: (bestTotal - second) / thumbs.length };
}

export function confident(plan) {
  return plan !== null && plan !== undefined && plan.margin >= CONFIDENT_MARGIN;
}

export { CONFIDENT_MARGIN };
