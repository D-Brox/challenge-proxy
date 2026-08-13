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

/**
 * Ensures cipher material is available, extracting it from the live site when
 * none is on disk. Returns a status, not the material.
 */
export async function loadOrExtractMaterial() {
  try {
    loadMaterial();
    return { ok: true, extracted: false };
  } catch (e) {
    try {
      await extract();
      cipherReload();
      return { ok: true, extracted: true };
    } catch (e2) {
      return { ok: false, extracted: false, error: String((e2 && e2.message) || e2) };
    }
  }
}
