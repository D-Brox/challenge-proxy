// comix-proxy: answers the comix.to API paths the comix extension consumes by running
// them through the site's own bundle, and maintains the Cloudflare clearance those
// requests need.
//
//   POST /request         { path, qs }             -> { json }
//   GET  /cookies          -> { cf_clearance, user_agent }
//   GET  /health           -> { oracle, cookies }
//
// The new site build has no `/api/v1` pass-through client left to ask: its API now lives
// in hidden store members that map every response into obfuscated view models. The
// oracle (lib/oracle.js) finds those members on the live bundle and applies an extracted
// reverse-mapper registry over their output, so this server still hands out plain JSON.
// A redeploy therefore needs no change here beyond a fresh registry if keys churn.
//
// `qs` arrives already canonicalized by the client (keys sorted, arrays expanded to
// `key[i]`, values raw) and is passed to the store members verbatim.
import http from 'node:http';
import { URL } from 'node:url';
import { apiRequest, rebuild, parseParams, oracleStats } from './lib/oracle.js';
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
    // A `{"e": ...}` body cannot be decoded on its own, so the request is reissued through
    // the site's own client instead of being replayed. See lib/oracle.js apiRequest.
    if (u.pathname === '/request' && req.method === 'POST') {
      const { path, qs, params } = await readJsonBody(req);
      if (!path) return send(res, 400, { error: 'missing path' });
      const resolved = params || parseParams(qs || '');
      Object.assign(detail, { path, qs: qs || undefined });
      // The client gives up at its own timeout, and by then a jar and a page load are
      // committed. Notice the hangup so the oracle stops instead of finishing a request
      // whose answer nobody will read.
      const gone = new AbortController();
      const onClose = () => { if (!res.writableEnded) gone.abort(); };
      res.on('close', onClose);
      let json;
      try {
        json = await apiRequest(path, resolved, { signal: gone.signal });
      } finally {
        res.off('close', onClose);
      }
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
        endpoints: ['/request', '/decrypt', '/cookies', '/health', '/refresh-material', '/load-material'],
      });
    }

    send(res, 404, { error: 'not found' });
  } catch (e) {
    // The caller hanging up is not a failure of anything, and logging it as one buries the
    // failures that are worth looking at.
    if (e && e.abandoned) {
      log.info(`client left before the answer was ready on ${req.method} ${u.pathname}`, { ...detail });
      return;
    }
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
