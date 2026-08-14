// Cipher material extraction. The cipher's S-boxes/keys are loaded into memory
// by the site's own secure-*.js bundle at boot, decoded through atob. The
// reliable way to capture them is to run the LIVE page in a real (headed)
// browser: pass the CF + WAF cookies, hook atob before any page script, then
// trigger the env module's api.chapters() so the cipher initializes.
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const MATERIAL_PATH = process.env.COMIX_MATERIAL || path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'material.json');
const CHROMIUM = process.env.CHROMIUM_PATH || '/usr/bin/chromium-browser';

// Headed Chromium needs a display; spin up Xvfb on demand (the container has
// no DISPLAY by default).
let xvfb = null;
function ensureDisplay() {
  if (process.env.DISPLAY) return;
  if (xvfb) return;
  xvfb = spawn('Xvfb', [':99', '-screen', '0', '1920x1080x24', '-nolisten', 'tcp'], { stdio: 'ignore' });
  process.env.DISPLAY = ':99';
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitForDisplay() {
  ensureDisplay();
  for (let i = 0; i < 50; i++) {
    try {
      fs.accessSync('/tmp/.X11-unix/X99');
      return;
    } catch (e) {
      await sleep(100);
    }
  }
}

// Runs the live title page in headed Chromium with atob hooks, then triggers
// the env module's api.chapters() so the cipher boots and the S-box/key
// material flows through atob. Returns the raw capture list.
async function captureMaterial() {
  const { chromium } = await import('playwright');
  const { ensureCookies } = await import('./waf.js');
  const cookies = await ensureCookies();
  await waitForDisplay();

  const browser = await chromium.launch({
    headless: false,
    executablePath: CHROMIUM,
    args: [
      '--no-sandbox',
      '--disable-dev-shm-usage',
      '--disable-blink-features=AutomationControlled',
      '--window-size=1920,1080',
    ],
  });

  const captures = [];
  try {
    const ctx = await browser.newContext({ userAgent: cookies.user_agent });
    await ctx.addCookies([
      { name: 'cf_clearance', value: cookies.cf_clearance, domain: 'comix.to', path: '/', httpOnly: true, secure: true },
      { name: 'waf_pass', value: cookies.waf_pass, domain: 'comix.to', path: '/', httpOnly: true, secure: true },
    ]);
    const page = await ctx.newPage();

    await page.addInitScript(() => {
      window.__trapped = [];
      const realAtob = window.atob.bind(window);
      Object.defineProperty(window, 'atob', {
        configurable: true,
        writable: true,
        value: (b64) => {
          const bin = realAtob(b64);
          let bytes = null;
          try { bytes = Array.from(bin, (c) => c.charCodeAt(0) & 0xff); } catch (e) {}
          window.__trapped.push({ b64: String(b64), len: bytes ? bytes.length : -1, bytes });
          return bin;
        },
      });
    });

    // The cipher initializes lazily on the first signed API call, so load a
    // title page and trigger the env module's own api.chapters().
    await page.goto('https://comix.to/title/506m-return-from-the-abyss', { waitUntil: 'domcontentloaded', timeout: 60000 });
    await page.waitForTimeout(10000);

    const result = await page.evaluate(`(async () => {
      try {
        const envUrl = performance.getEntriesByType('resource').map(e => e.name).find(n => /\\/env-[\\w-]+\\.js/.test(n));
        if (!envUrl) return { phase: 'no env url', trapped: (window.__trapped||[]) };
        let mod;
        try { mod = await import(envUrl); }
        catch (e) { return { phase: 'import failed: ' + (e && e.message), trapped: (window.__trapped||[]) }; }
        const findApi = (m) => {
          if (!m) return null;
          if (m.c && typeof m.c.chapters === 'function') return m.c;
          for (const v of Object.values(m))
            if (v && typeof v === 'object' && typeof v.chapters === 'function') return v;
          return null;
        };
        const api = findApi(mod) || findApi(mod.default);
        if (!api) return { phase: 'no api found', trapped: (window.__trapped||[]) };
        try { await api.chapters('506m', { page: 1, limit: 20, order: { number: 'desc' } }); }
        catch (e) { return { phase: 'chapters() threw: ' + (e && e.message), trapped: (window.__trapped||[]) }; }
        return { phase: 'ok', trapped: (window.__trapped||[]) };
      } catch (e) {
        return { phase: 'outer: ' + (e && e.message), trapped: (window.__trapped||[]) };
      }
    })()`);

    for (const c of result.trapped || []) {
      if (c.bytes) captures.push({ kind: 'atob', len: c.len, bytes: c.bytes, arg: c.b64 });
    }
    if (result.phase !== 'ok') {
      throw new Error(`live capture: ${result.phase}`);
    }
  } finally {
    await browser.close();
  }
  return captures;
}

// Extracts material from captured calls. Mirrors ComixMaterial.extractFrom.
function extractMaterial(captures) {
  const atobCalls = captures
    .filter((c) => c.kind === 'atob' && c.bytes)
    .map((c) => Buffer.from(c.bytes));
  if (atobCalls.length < 3) return null;

  const sboxes = [];
  const keys = [];
  for (const b of atobCalls) {
    if (b.length === 256) sboxes.push([...b]);
    else if (b.length === 24 || b.length === 32) keys.push([...b]);
  }
  if (sboxes.length < 3 || keys.length < 3) return null;
  return {
    sboxes: sboxes.slice(0, 3),
    keys: keys.slice(0, 3),
  };
}

export async function extractAndSaveMaterial() {
  const captures = await captureMaterial();
  const material = extractMaterial(captures);
  if (!material) {
    throw new Error(`Could not derive material from ${captures.length} captures (${captures.map((c) => c.len).join(',')})`);
  }
  fs.writeFileSync(MATERIAL_PATH, JSON.stringify(material));
  return material;
}
