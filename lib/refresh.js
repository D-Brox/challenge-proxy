// Material refresh bridge: re-extracts cipher material from the live site via
// Playwright (extract.js) and hot-reloads it into cipher.js.
import { extractAndSaveMaterial as extract } from './extract.js';
import { loadMaterial, reloadMaterial as cipherReload } from './cipher.js';

export async function extractAndSaveMaterial() {
  const material = await extract();
  const reloaded = cipherReload();
  const checksum = (arr) => arr.slice(0, 8).map((b) => b.toString(16).padStart(2, '0')).join('');
  return {
    sboxes: reloaded.sboxes.map(checksum),
    keys: reloaded.keys.map(checksum),
  };
}

export function reloadMaterial() {
  const material = loadMaterial();
  const checksum = (arr) => arr.slice(0, 8).map((b) => b.toString(16).padStart(2, '0')).join('');
  return {
    sboxes: material.sboxes.map(checksum),
    keys: material.keys.map(checksum),
  };
}
