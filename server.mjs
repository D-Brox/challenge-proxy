// comix-proxy: mints signed `_` tokens and maintains WAF cookies for the
// comix.to API. The extension calls GET /sign to get everything it needs to
// issue one signed request directly.
//
//   GET /sign?path=/api/v1/manga/...&qs=<canonical>
//   -> { token, waf_pass, cf_clearance, user_agent }
//
//   GET /refresh-material   -> re-extracts cipher material from the live site
//   GET /health             -> { material: {...}, cookies: {...} }
import http from 'node:http';
import { URL } from 'node:url';
import { loadMaterial, generateUnderscore, decryptE } from './lib/cipher.js';
import { ensureCookies, getCfClearance } from './lib/waf.js';
import { extractAndSaveMaterial, loadOrExtractMaterial } from './lib/refresh.js';

const PORT = Number(process.env.PORT || 9191);
const REFRESH_TOKEN = process.env.REFRESH_TOKEN || '';

function send(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'Access-Control-Allow-Origin': '*',
  });
  res.end(body);
}

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  try {
    if (u.pathname === '/sign' && req.method === 'GET') {
      const path = u.searchParams.get('path');
      const qs = u.searchParams.get('qs') || '';
      if (!path) return send(res, 400, { error: 'missing path' });
      const token = generateUnderscore(path, qs);
      const force = u.searchParams.get('force') === '1';
      const cookies = await ensureCookies(force);
      return send(res, 200, { token, ...cookies });
    }

    if (u.pathname === '/decrypt' && req.method === 'GET') {
      const e = u.searchParams.get('e');
      if (!e) return send(res, 400, { error: 'missing e' });
      return send(res, 200, { json: decryptE(e).toString('utf8') });
    }

    if (u.pathname === '/cookies' && req.method === 'GET') {
      const force = u.searchParams.get('force') === '1';
      const cookies = await ensureCookies(force);
      return send(res, 200, cookies);
    }

    if (u.pathname === '/material' && req.method === 'GET') {
      const mat = loadMaterial();
      const b64 = (arr) => Buffer.from(arr).toString('base64');
      return send(res, 200, { s: mat.sboxes.map(b64), k: mat.keys.map(b64) });
    }

    if (u.pathname === '/refresh-material' && req.method === 'POST') {
      if (REFRESH_TOKEN && u.searchParams.get('token') !== REFRESH_TOKEN) {
        return send(res, 403, { error: 'bad token' });
      }
      const material = await extractAndSaveMaterial();
      return send(res, 200, { material });
    }

    if (u.pathname === '/load-material' && req.method === 'POST') {
      const status = await loadOrExtractMaterial();
      return send(res, status.ok ? 200 : 500, status);
    }

    if (u.pathname === '/health' && req.method === 'GET') {
      let cookies = { error: 'not yet solved' };
      try {
        const cf = await getCfClearance();
        cookies = { user_agent: cf.userAgent, has_cf: !!cf.value };
      } catch (e) {
        cookies.error = String(e.message || e);
      }
      const mat = loadMaterial();
      return send(res, 200, {
        status: 'ok',
        material: {
          sbox0: mat.sboxes[0].slice(0, 8),
          keys: mat.keys.map((k) => k.length),
        },
        cookies,
      });
    }

    if (u.pathname === '/' || u.pathname === '') {
      return send(res, 200, {
        endpoints: ['/sign', '/decrypt', '/cookies', '/material', '/refresh-material', '/load-material', '/health'],
      });
    }

    send(res, 404, { error: 'not found' });
  } catch (e) {
    send(res, 500, { error: String((e && e.message) || e) });
  }
});

server.listen(PORT, () => {
  console.log(`comix-proxy listening on :${PORT}`);
  try {
    const mat = loadMaterial();
    console.log(`material: sboxes=${mat.sboxes.map((s) => s.length).join('/')} keys=${mat.keys.map((k) => k.length).join('/')}`);
  } catch (e) {
    console.log(`material: not yet extracted (call POST /load-material to bootstrap)`);
  }
  (async () => {
    for (let attempt = 1; attempt <= 5; attempt++) {
      try {
        const c = await ensureCookies();
        console.log(`cookies: ready (cf_clearance=${c.cf_clearance.length} chars, waf_pass ready)`);
        return;
      } catch (e) {
        console.log(`cookies: pre-solve attempt ${attempt} failed: ${(e && e.message) || e}`);
        await new Promise((r) => setTimeout(r, 5000));
      }
    }
    console.log('cookies: pre-solve failed after 5 attempts (will solve on demand)');
  })();
});
