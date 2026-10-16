// comix-proxy: mints signed `_` tokens and decodes protected bodies for the
// comix.to API, and maintains the Cloudflare clearance those requests need.
//
//   GET  /sign?path=/api/v1/manga/...&qs=<canonical>
//        -> { token }
//   POST /request         { path, qs }             -> { json }
//   GET  /cookies          -> { cf_clearance, user_agent }
//   GET  /health           -> { oracle, cookies }
//
// The site's crypto now lives behind a bytecode VM that is rebuilt on every deploy,
// so it is not reimplemented here: lib/oracle.js keeps the real bundle loaded in a
// headless Chromium and asks it. A redeploy therefore needs no change here.
//
// `qs` arrives already canonicalized by the client (keys sorted, arrays expanded to
// `key[i]`, values raw) and is used verbatim - re-encoding it would change what the
// token covers.
import http from 'node:http';
import { URL } from 'node:url';
import { signedUrl, apiRequest, rebuild, parseParams, oracleStats } from './lib/oracle.js';
import { getCfClearance, jarBufferStats, keepBufferFull } from './lib/waf.js';
import { log, bodySummary } from './lib/log.js';

const PORT = Number(process.env.PORT || 9191);
const REFRESH_TOKEN = process.env.REFRESH_TOKEN || '';
const MAX_BODY_BYTES = 4 * 1024 * 1024;
const LOG_STACK = /^(1|true)$/i.test(process.env.LOG_STACK || '');

function send(res, code, obj) {
  res.writeHead(code, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'Access-Control-Allow-Origin': '*',
  });
  res.end(JSON.stringify(obj));
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error('body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch (e) {
        reject(new Error(`bad JSON body: ${e.message}`));
      }
    });
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const started = Date.now();
  // handlers add what they learn about the call; it rides out on the access line
  const detail = {};
  res.on('finish', () => {
    log.info(`${req.method} ${u.pathname}`, {
      status: res.statusCode,
      ms: Date.now() - started,
      ...detail,
    });
  });

  try {
    if (u.pathname === '/sign' && req.method === 'GET') {
      const path = u.searchParams.get('path');
      if (!path) return send(res, 400, { error: 'missing path' });
      const qs = u.searchParams.get('qs') || '';
      Object.assign(detail, { path });
      // The site builds and signs the request itself; the token comes off the wire.
      const url = await signedUrl(path, parseParams(qs));
      const token = url.match(/[?&]_=([^&]+)/);
      if (!token) return send(res, 502, { error: 'site produced no token', url });
      // The signed URL is not handed to the caller: a jar buys about one API call, so
      // sending the cookies with it would leave them spent. Callers wanting the clearance
      // itself ask /cookies.
      return send(res, 200, { token: decodeURIComponent(token[1]) });
    }

    // A `{"e": ...}` body cannot be decoded on its own, so the request is reissued through
    // the site's own client instead of being replayed. See lib/oracle.js apiRequest.
    if (u.pathname === '/request' && req.method === 'POST') {
      const { path, qs, params } = await readJsonBody(req);
      if (!path) return send(res, 400, { error: 'missing path' });
      const resolved = params || parseParams(qs || '');
      Object.assign(detail, { path, qs: qs || undefined });
      const json = await apiRequest(path, resolved);
      Object.assign(detail, bodySummary(json));
      return send(res, 200, { json });
    }

    if (u.pathname === '/decrypt' && req.method === 'POST') {
      return send(res, 410, {
        error: 'envelopes are not decodable offline; the bundle exposes no decoder. '
          + 'POST /request with { path, qs } instead.',
      });
    }

    // The jar currently in use. It is spent by definition - every request gets its own - so
    // this is for inspection, not for making requests with.
    if (u.pathname === '/cookies' && req.method === 'GET') {
      const cf = await getCfClearance();
      return send(res, 200, {
        cf_clearance: cf.value,
        user_agent: cf.userAgent,
        cookie: cf.jar,
      });
    }

    // The client calls these to recover from a redeploy. With the oracle there is no
    // material on disk to re-extract, so both just make sure the live bundle is loaded.
    if (u.pathname === '/refresh-material' && req.method === 'POST') {
      if (REFRESH_TOKEN && u.searchParams.get('token') !== REFRESH_TOKEN) {
        return send(res, 403, { error: 'bad token' });
      }
      const ready = await rebuild();
      return send(res, ready ? 200 : 503, { material: { mode: 'oracle', ready } });
    }

    if (u.pathname === '/load-material' && req.method === 'POST') {
      const stats = oracleStats();
      return send(res, stats.ready ? 200 : 503, {
        ok: stats.ready,
        extracted: false,
        mode: 'oracle',
      });
    }

    if (u.pathname === '/health' && req.method === 'GET') {
      let cookies = { error: 'not yet solved' };
      try {
        const cf = await getCfClearance();
        cookies = { user_agent: cf.userAgent, has_cf: !!cf.value };
      } catch (e) {
        cookies.error = String(e.message || e);
      }
      return send(res, 200, { status: 'ok', oracle: oracleStats(), cookies, jars: jarBufferStats() });
    }

    if (u.pathname === '/' || u.pathname === '') {
      return send(res, 200, {
        endpoints: ['/sign', '/request', '/decrypt', '/cookies', '/health', '/refresh-material', '/load-material'],
      });
    }

    send(res, 404, { error: 'not found' });
  } catch (e) {
    // the stack is what tells a spent cookie jar apart from a real endpoint change
    log.error(`unhandled failure on ${req.method} ${u.pathname}`, {
      error: String((e && e.message) || e),
      ...detail,
      stack: LOG_STACK ? String((e && e.stack) || '').split('\n').slice(0, 4) : undefined,
    });
    send(res, 500, { error: String((e && e.message) || e) });
  }
});

server.listen(PORT, () => {
  log.info('comix-proxy listening', { port: PORT, flaresolverr: process.env.FLARESOLVERR_URL || 'default', logLevel: process.env.LOG_LEVEL || 'info' });
});

// Every request consumes a cookie jar and FlareSolverr needs ~11s to mint one, so they are
// solved from startup rather than on demand - otherwise the first request after a restart
// waits a solve, and a burst after an idle spell waits several.
keepBufferFull();

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, async () => {
    const { shutdown } = await import('./lib/oracle.js');
    await shutdown();
    process.exit(0);
  });
}
