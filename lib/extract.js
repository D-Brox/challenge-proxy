// Cipher material extraction. Follows the browse page's module graph
// (main-*.js -> env/secure/vendor/rolldown-runtime), fetches the bundles via
// FlareSolverr (they are served as HTML "view source" wrappers with mojibake
// identifiers), then runs env.js in a real Chromium with atob/TextDecoder
// hooks to capture the S-box/key material the cipher uses at boot.
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const MATERIAL_PATH = process.env.COMIX_MATERIAL || path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'material.json');
const FS_BASE = process.env.FLARESOLVERR_URL || 'http://flaresolverr:8191/v1';
const BUNDLE_IMPORT_REGEX = /(?:import\s*\(\s*)?["']\.?\/([^"']+\.js)["']/g;
const CIPHER_BUNDLE_PREFIXES = ['env-', 'secure-', 'vendor-', 'rolldown-runtime-'];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function fsFetch(url) {
  const res = await fetch(FS_BASE, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      cmd: 'request.get',
      url,
      maxTimeout: 60000,
      session: 'comix-bundles',
    }),
  });
  const j = await res.json();
  if (j.status !== 'ok' || !j.solution) {
    throw new Error(`FlareSolverr bundle fetch: ${j.message || JSON.stringify(j).slice(0, 200)}`);
  }
  return j.solution.response;
}

// The asset server wraps every bundle in an HTML "view source" document
// (<html>...<pre>...import{...}</pre></html>). Extract the <pre> body and
// decode its HTML entities.
function unwrapHtmlWrappedJs(text) {
  const head = text.trimStart();
  if (!/^<!doctype/i.test(head) && !/^<html/i.test(head)) return text;
  const m = head.match(/<pre[^>]*>([\s\S]*?)<\/pre>/i);
  if (!m) return text;
  return m[1].replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"').replace(/&#x27;/g, "'").replace(/&#39;/g, "'")
    .replace(/&nbsp;/g, ' ');
}

// Bundles are served with UTF-8 decoded as cp1252 and re-encoded as UTF-8,
// so non-ASCII identifiers arrive as mojibake. Reverses it byte-for-byte.
function recoverMojibake(text) {
  let out = Buffer.alloc(text.length);
  let n = 0;
  for (const ch of text) {
    const code = ch.codePointAt(0);
    if (code <= 0xff) {
      out[n++] = code;
    } else {
      const b = Buffer.from(ch, 'latin1');
      for (let i = 0; i < b.length; i++) out[n++] = b[i];
    }
  }
  return out.subarray(0, n);
}

async function fetchBrowsePage() {
  const text = await fsFetch('https://comix.to/browse');
  const m = text.match(/<script[^>]+type="module"[^>]+src="([^"]+)"/i);
  if (!m) throw new Error('No module entry script in browse page');
  return { mainUrl: m[1].startsWith('http') ? m[1] : 'https://comix.to' + m[1] };
}

async function discoverBundles() {
  const { mainUrl } = await fetchBrowsePage();
  const mainDir = mainUrl.substring(0, mainUrl.lastIndexOf('/') + 1);
  const mainText = unwrapHtmlWrappedJs(await fsFetch(mainUrl));
  const mainJs = recoverMojibake(mainText).toString('utf8');
  const names = [];
  for (const m of mainJs.matchAll(BUNDLE_IMPORT_REGEX)) {
    const name = m[1];
    if (CIPHER_BUNDLE_PREFIXES.some((p) => name.startsWith(p))) names.push(name);
  }
  const distinct = [...new Set(names)];
  if (!distinct.length || !distinct.some((n) => n.startsWith('env-'))) {
    throw new Error(`No cipher bundles in ${mainUrl}: ${distinct.join(',')}`);
  }
  const bundles = {};
  for (const name of distinct) {
    const url = mainDir + name;
    const wrapped = await fsFetch(url);
    const js = recoverMojibake(unwrapHtmlWrappedJs(wrapped));
    bundles[name] = js;
  }
  return { mainDir, bundles };
}

// Runs env.js in Chromium with hooks, capturing the atob/TextDecoder calls
// the cipher makes at boot. Returns the raw capture list.
export async function captureMaterial(bundles) {
  const MIME = { '.js': 'text/javascript', '.html': 'text/html' };
  const server = http.createServer((req, res) => {
    const urlPath = decodeURIComponent(new URL(req.url, 'http://x').pathname);
    const file = urlPath.replace(/^\//, '');
    const bytes = bundles[file];
    if (!bytes) {
      res.writeHead(404);
      res.end('nf');
      return;
    }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'text/javascript' });
    res.end(bytes);
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;

  // env.js imports ./secure-*.js and ./vendor-*.js relative to itself; we serve
  // bundles at the root so rewrite relative imports to absolute paths.
  let envJs = bundles[Object.keys(bundles).find((n) => n.startsWith('env-'))].toString('utf8');
  envJs = envJs.replace(/from"\.\/([^"]+\.js)"/g, 'from"/$1"');
  const envName = 'env.mjs';
  bundles[envName] = Buffer.from(envJs, 'utf8');

  fs.writeFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '.extract-index.html'),
    `<!doctype html><html><body><script type="module">
import('/${envName}').catch(e => document.body.setAttribute('data-err', String(e && e.message || e) + '||' + (e && e.stack || '').slice(0, 300)));
</script></body></html>`,
  );

  const executablePath = process.env.CHROMIUM_PATH;
  const { chromium } = await import('playwright');
  const browser = await chromium.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-dev-shm-usage'],
    ...(executablePath ? { executablePath } : {}),
  });
  const page = await browser.newPage();

  const captures = [];
  await page.addInitScript(() => {
    const cap = (kind, arg, ret) => {
      if (!window.__trapped) window.__trapped = [];
      let bytes = null;
      try {
        if (kind === 'atob') {
          const bin = atob(arg);
          bytes = Array.from(bin, (c) => c.charCodeAt(0) & 0xff);
        } else if (kind === 'TextDecoder') {
          bytes = Array.from(new Uint8Array(arg));
        }
      } catch (e) { /* ignore */ }
      window.__trapped.push({ kind, arg, len: bytes ? bytes.length : -1, bytes });
      return ret;
    };
    const realAtob = window.atob.bind(window);
    window.atob = (b64) => cap('atob', b64, realAtob(b64));
    const realTD = window.TextDecoder;
    window.TextDecoder = class extends realTD {
      constructor(...a) { super(...a); }
      decode(input, ...rest) {
        if (input && input instanceof ArrayBuffer) {
          cap('TextDecoder', input, undefined);
        } else if (input && input.buffer) {
          cap('TextDecoder', input.buffer, undefined);
        }
        return super.decode(input, ...rest);
      }
    };
  });

  try {
    await page.goto(`http://127.0.0.1:${port}/`, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(4000);
    const trapped = await page.evaluate(() => window.__trapped || []);
    for (const c of trapped) captures.push(c);
  } finally {
    await browser.close();
    server.close();
    fs.unlinkSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '.extract-index.html'));
  }
  return captures;
}

// Extracts material from captured calls. Mirrors ComixMaterial.extractFrom.
export function extractMaterial(captures) {
  const atobCalls = captures
    .filter((c) => c.kind === 'atob' && c.bytes)
    .map((c) => Buffer.from(c.bytes));
  if (atobCalls.length < 3) return null;

  // 3 sboxes (256 bytes each) + 3 keys (24/24/32 bytes), interleaved by the
  // cipher's boot sequence: first 3 x 256, then the keys.
  const sizes = atobCalls.map((b) => b.length);
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
  const bundles = await discoverBundles();
  const captures = await captureMaterial(bundles);
  const material = extractMaterial(captures);
  if (!material) {
    throw new Error(`Could not derive material from ${captures.length} captures (${captures.map((c) => c.len).join(',')})`);
  }
  fs.writeFileSync(MATERIAL_PATH, JSON.stringify(material));
  return material;
}

// Validates the captured material against a known-good token if provided.
export { sleep };
