// Crypto oracle: a long-lived headless Chromium that keeps the site's own bundle
// loaded so requests can be signed through it.
//
// The bundle re-obfuscates on every deploy and its primitives sit behind a bytecode
// VM, so nothing here is reimplemented - the real bundle is asked instead. Nothing
// depends on a minified name either:
//
//   * The site's API function for a path is found by matching the *shape* of the path
//     against the route table it exports (e.g. /api/v1/manga/<hid>/chapters matches the
//     table entry `/manga/${a}/chapters`), so the key can change every deploy.
//   * Calling that function with the caller's parameters makes the site build, sign and
//     send its own request. The URL is taken off the wire just before it goes out, and
//     the extension issues it natively from there.
//   - The manga list is not in the route table at all, so that one is signed by letting
//     the site issue it: the browse page is loaded with the caller's parameters and the
//     request is captured as it leaves.
//
// Cloudflare clearance is bound to the user agent it was solved with and the site also
// sets a `session` cookie, so the whole jar travels together and the UA is fixed to match.
import { chromium } from 'playwright';
import { getCfClearance } from './waf.js';
import { log } from './log.js';

const BASE = process.env.COMIX_BASE || 'https://comix.to';
const READY_TIMEOUT_MS = Number(process.env.ORACLE_READY_TIMEOUT_MS || 45000);
const EVAL_TIMEOUT_MS = Number(process.env.ORACLE_EVAL_TIMEOUT_MS || 20000);
// Importing the bundle's module graph and waiting for the dispatch takes longer than a
// plain evaluation, so signing gets its own budget.
const SIGN_TIMEOUT_MS = Number(process.env.ORACLE_SIGN_TIMEOUT_MS || 45000);
const CAPTURE_TIMEOUT_MS = Number(process.env.ORACLE_CAPTURE_TIMEOUT_MS || 20000);
// The site gates each cookie jar to about this many API calls before it starts answering
// 403 captcha_required, which its own client turns into a promise that never settles.
// Measured at 2 per jar, repeatably, and a freshly solved jar restores the budget, so the
// jar is rotated rather than waiting the window out.
const API_CALLS_PER_JAR = Number(process.env.ORACLE_API_CALLS_PER_JAR || 2);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let browser = null;
let context = null;
let page = null;
let ready = false;
let building = null;
let jarCalls = 0;
const stats = {
  signs: 0, navigations: 0, decrypts: 0, rebuilds: 0, rotations: 0,
  readyAt: null, lastKind: null,
};

/**
 * page.evaluate has no timeout of its own, so a busy main thread would hang forever.
 * It also forwards exactly one argument, so anything the page side needs travels as a
 * single value.
 */
async function evaluateWithin(fn, arg, ms, label) {
  let timer;
  try {
    return await Promise.race([
      page.evaluate(fn, arg),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function closeAll() {
  for (const closer of [page, context, browser]) {
    try {
      if (closer) await closer.close();
    } catch { /* already gone */ }
  }
  page = null;
  context = null;
  browser = null;
  ready = false;
}

/**
 * Builds a page that has cleared Cloudflare and finished booting the bundle. A page
 * that has not booted will hand back unsigned requests, so this waits for the bundle
 * rather than for the load event.
 */
async function build() {
  await closeAll();
  log.debug('building oracle');
  let cf;
  try {
    cf = await getCfClearance();
  } catch (e) {
    log.error('could not obtain cookies to build the oracle', { error: String((e && e.message) || e) });
    throw e;
  }

  browser = await chromium.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-dev-shm-usage'],
    ...(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {}),
  });
  context = await browser.newContext({ userAgent: cf.userAgent });
  // The whole jar: without `session` alongside cf_clearance the page never boots.
  await context.addCookies(cf.cookies.map((c) => ({
    name: c.name,
    value: c.value,
    domain: c.domain,
    path: c.path || '/',
  })));
  page = await context.newPage();

  const started = Date.now();
  await page.goto(`${BASE}/browse`, { waitUntil: 'domcontentloaded', timeout: 90000 }).catch(() => {});
  // The bundle publishes its API table a little after the load event
  const deadline = Date.now() + READY_TIMEOUT_MS;
  let last = {};
  while (Date.now() < deadline) {
    const probe = await evaluateWithin(async () => {
      const scripts = performance.getEntriesByType('resource').map((e) => e.name)
        .filter((u) => /\/assets\/.*\.js$/.test(u));
      return {
        ready: scripts.some((u) => /\/main-[^/]+\.js$/.test(u)) && scripts.length > 3,
        // A jar the site no longer trusts bounces the page to its challenge instead of
        // loading the bundle, so there is nothing to wait for.
        challenged: /\/@waf|challenge|just a moment/i.test(`${location.pathname} ${document.title}`),
        url: location.href,
        title: document.title,
        scripts: scripts.length,
      };
    }, undefined, 10000, 'readiness probe').catch((e) => ({ error: String((e && e.message) || e) }));
    last = probe || {};
    if (last.ready) {
      ready = true;
      stats.readyAt = Date.now() - started;
      log.info('oracle ready', { ms: stats.readyAt, cookies: cf.cookies.length });
      return;
    }
    if (last.challenged) {
      log.warn('oracle was bounced to the security check', { url: last.url, title: last.title });
      break;
    }
    await sleep(500);
  }
  log.error('oracle never became ready', { waitedMs: Date.now() - started, ...last });
  // The jar this page was built on is the likely reason. Drop it, so the retry is not the
  // same page rebuilt on the same dead cookies - that is what wedged self-healing before.
  await closeAll();
  try {
    await getCfClearance(true);
    log.info('re-solved cookies after a failed boot');
  } catch (e) {
    log.error('could not re-solve cookies after a failed boot', { error: String((e && e.message) || e) });
  }
}

/** Brings the oracle up, sharing one build between concurrent callers. */
async function ensure() {
  if (ready) return true;
  if (!building) building = build().finally(() => { building = null; });
  await building;
  return ready;
}

/**
 * Charges one API call against the current cookie jar, rotating the jar first when the
 * budget for it is gone. Rotating solves a new cf_clearance and rebuilds the page on it,
 * which is what actually restores the site's willingness to answer.
 */
async function spendJarCall() {
  if (jarCalls >= API_CALLS_PER_JAR) {
    stats.rotations++;
    // The site allows only a couple of API calls per cookie jar and then stops answering,
    // so this is expected traffic, not a fault.
    log.info('rotating cookie jar', { used: jarCalls, budget: API_CALLS_PER_JAR });
    await getCfClearance(true);
    await closeAll();
    await ensure();
    jarCalls = 0;
  }
  jarCalls++;
}

/** Retries once through a fresh page, for a bundle that reloaded or got redeployed. */
// Three, because a failed boot now re-solves the cookies and the next build starts on a
// jar the site still trusts; two left no room for that to pay off.
const MAX_ATTEMPTS = Number(process.env.ORACLE_MAX_ATTEMPTS || 3);

async function withRetry(what, run) {
  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    if (await ensure()) {
      try {
        return await run();
      } catch (e) {
        const error = String((e && e.message) || e);
        if (attempt === MAX_ATTEMPTS - 1) {
          log.error(`${what} failed on every attempt`, { attempts: MAX_ATTEMPTS, error });
          throw e;
        }
        // A failed attempt is the site's usual way of saying the material moved on.
        log.warn(`${what} failed, rebuilding the oracle`, { attempt: attempt + 1, of: MAX_ATTEMPTS, error });
      }
    }
    stats.rebuilds++;
    await closeAll();
  }
  const error = `${what} failed: oracle would not come up`;
  log.error(error, { attempts: MAX_ATTEMPTS });
  throw new Error(error);
}

/**
 * Runs inside the page. Finds the API function implementing the shape of `path` in the
 * route table the bundle exports, calls it, and hands back the URL the site was about
 * to send. Matching on shape rather than name is what survives a redeploy.
 */
const SIGN_VIA_ROUTE_JS = `
async function (spec) {
  var concrete = spec.path.replace(/^\\/api\\/v1/, '').split('/').filter(Boolean);
  var captured = null;

  var realOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (m, url) {
    captured = String(url);
    XMLHttpRequest.prototype.open = realOpen;
    return realOpen.apply(this, arguments);
  };
  try {
    var scripts = performance.getEntriesByType('resource').map(function (e) { return e.name; })
      .filter(function (u) { return /\\/assets\\/.*\\.js$/.test(u); });
    var exportsList = [];
    for (var url of new Set(scripts)) {
      try { exportsList.push(...Object.values(await import(url))); } catch (e) {}
    }

    for (var holder of exportsList) {
      if (!holder || typeof holder !== 'object') continue;
      for (var table of Object.values(holder)) {
        if (!table || typeof table !== 'object') continue;
        var keys = Object.keys(table);
        for (var key of keys) {
          var fn = table[key];
          if (typeof fn !== 'function') continue;
          var m = String(fn).match(/^[\\s\\S]{0,40}=>\`([^\`]+)\`\\s*$/);
          if (!m) continue;
          var parts = m[1].split('/').filter(Boolean);
          if (parts.length !== concrete.length) continue;
          // every literal segment of the template has to line up with the request
          var args = [];
          var fits = true;
          for (var i = 0; i < parts.length; i++) {
            if (parts[i].indexOf('\${') !== -1) args.push(concrete[i]);
            else if (parts[i] !== concrete[i]) { fits = false; break; }
          }
          if (!fits) continue;
          var api = exportsList.find(function (v) {
            return v && typeof v === 'object' && v !== table &&
              typeof v[key] === 'function' && keys.every(function (n) { return n in v; });
          });
          if (!api) continue;
          try {
            api[key].apply(api, args.concat([spec.params || {}]));
            // the client dispatches through a promise chain, so the request only reaches
            // the wire after this call returns
            await new Promise(function (r) { setTimeout(r, 2500); });
            return { url: captured, route: m[1], key: key };
          } catch (e) {
            return { error: String((e && e.message) || e).slice(0, 160) };
          }
        }
      }
    }
    return { error: 'no route matched ' + spec.path };
  } finally {
    XMLHttpRequest.prototype.open = realOpen;
  }
}
`;

/** Loads the browse page with the caller's parameters and takes the URL the site sends. */
async function signViaBrowse(path, params) {
  const query = Object.entries(params || {})
    .map(([k, v]) => {
      const values = Array.isArray(v) ? v : [v];
      return values.map((x, i) => `${values.length > 1 ? `${k}[${i}]` : k}=${x}`).join('&');
    })
    .join('&');
  const captured = [];
  const listener = (request) => {
    if (request.url().includes('/api/v1/manga')) captured.push(request.url());
  };
  page.on('request', listener);

  const browseParams = { ...params, order: params.order };
  await page.goto(`${BASE}/browse${query ? `?${query}` : ''}`, {
    waitUntil: 'domcontentloaded',
    timeout: 90000,
  }).catch(() => {});

  const deadline = Date.now() + CAPTURE_TIMEOUT_MS;
  while (Date.now() < deadline && !captured.length) await sleep(250);
  page.off('request', listener);
  stats.navigations++;
  return captured[0] || null;
}

/**
 * A fully signed URL for `path` with `params`, exactly as the site would send it.
 * Throws when no signed URL could be produced.
 */
export async function signedUrl(path, params = {}) {
  const run = async () => {
    await spendJarCall();
    // Playwright forwards one argument and never a string body, so the page-side source
    // travels as data and is instantiated there.
    const viaRoute = await evaluateWithin(
      (pair) => (0, eval)('(' + pair[0] + ')')(pair[1]),
      [SIGN_VIA_ROUTE_JS, { path, params }],
      SIGN_TIMEOUT_MS,
      'route signing',
    ).catch((e) => ({ error: e.message }));
    if (viaRoute && viaRoute.url) {
      stats.lastKind = 'route';
      return new URL(viaRoute.url, BASE).toString();
    }
    // No route table entry fits (the manga list is built inline), so let the site
    // assemble and sign the request itself and read it off the wire.
    if (path.replace(/^\/api\/v1/, '') === '/manga') {
      const url = await signViaBrowse(path, params);
      if (url) {
        stats.lastKind = 'browse';
        return url;
      }
    }
    throw new Error(`could not sign ${path}: ${viaRoute?.error || 'no request was made'}`);
  };
  try {
    const url = await withRetry('sign', run);
    stats.signs++;
    return url;
  } catch (e) {
    jarCalls = API_CALLS_PER_JAR;
    throw e;
  }
}

/** The `_` token on a signed URL, which is all a caller needs to rebuild the request. */
export async function sign(canonicalPathAndQuery) {
  const [path, query] = canonicalPathAndQuery.split('?');
  const params = {};
  for (const pair of (query || '').split('&').filter(Boolean)) {
    const eq = pair.indexOf('=');
    const name = eq === -1 ? pair : pair.slice(0, eq);
    const value = eq === -1 ? '' : decodeURIComponent(pair.slice(eq + 1).replace(/\+/g, ' '));
    const base = name.replace(/\[\d+\]$/, '');
    if (!params[base]) params[base] = [];
    params[base].push(value);
  }
  const flat = {};
  for (const [k, v] of Object.entries(params)) flat[k] = v.length === 1 ? v[0] : v;
  const url = await signedUrl(path, flat);
  const token = url.match(/[?&]_=([^&]+)/);
  if (!token) throw new Error(`signed URL carried no token: ${url}`);
  return decodeURIComponent(token[1]);
}

/**
 * Turns the client's canonical query back into the nested shape the site's API
 * function expects: `order[created_at]=desc` is `{order: {created_at: 'desc'}}` and
 * repeated `content_rating[]=` values are an array.
 */
export function parseParams(qs) {
  const out = {};
  for (const pair of String(qs || '').split('&').filter(Boolean)) {
    const eq = pair.indexOf('=');
    const rawName = eq === -1 ? pair : pair.slice(0, eq);
    const value = eq === -1 ? '' : decodeURIComponent(pair.slice(eq + 1).replace(/\+/g, ' '));
    const segments = rawName.split('[').map((s) => s.replace(/\]$/, ''));
    const leaf = segments.pop();
    let node = out;
    for (const seg of segments) {
      if (typeof node[seg] !== 'object' || node[seg] === null) node[seg] = {};
      node = node[seg];
    }
    if (leaf === '') {
      if (!Array.isArray(node.__list)) node.__list = [];
      node.__list.push(value);
    } else {
      if (node[leaf] === undefined) node[leaf] = value;
      else if (Array.isArray(node[leaf])) node[leaf].push(value);
      else node[leaf] = [node[leaf], value];
    }
  }
  for (const key of Object.keys(out)) {
    if (out[key] && typeof out[key] === 'object' && Array.isArray(out[key].__list)) out[key] = out[key].__list;
  }
  return out;
}

/**
 * Runs inside the page. Issues the request through the site's own API client, so the bundle
 * signs it and unwraps the `{"e": ...}` envelope itself.
 *
 * Nothing here names a minified symbol: the client module is picked by the shape of its
 * exports (an object whose members are all functions, one of which wraps the axios GET),
 * so the route survives a redeploy the way SIGN_VIA_ROUTE_JS does.
 */
const REQUEST_VIA_CLIENT_JS = `
async function (spec) {
  var CACHE = '__oracleApiClient';
  if (!window[CACHE]) {
    var urls = performance.getEntriesByType('resource').map(function (e) { return e.name; })
      .filter(function (u) { return /\\/assets\\/.*\\.js$/.test(u); });
    for (var s of document.querySelectorAll('script[type="module"]')) if (s.src) urls.push(s.src);
    urls = Array.from(new Set(urls));
    for (var url of urls) {
      var mod;
      try { mod = await import(url); } catch (e) { continue; }
      for (var value of Object.values(mod)) {
        if (!value || typeof value !== 'object' || Array.isArray(value)) continue;
        var members = Object.entries(value).filter(function (p) { return typeof p[1] === 'function'; });
        if (members.length < 3) continue;
        var get = members.find(function (p) { return /\\.get\\s*\\(/.test(String(p[1])); });
        if (!get) continue;
        window[CACHE] = { api: value, key: get[0] };
        break;
      }
      if (window[CACHE]) break;
    }
    if (!window[CACHE]) return { error: 'no api client among ' + urls.length + ' module(s)' };
  }
  try {
    var data = await window[CACHE].api[window[CACHE].key](
      spec.path, spec.params ? { params: spec.params } : undefined);
    return { json: typeof data === 'string' ? data : JSON.stringify(data) };
  } catch (e) {
    return { error: String((e && e.message) || e).slice(0, 300) };
  }
}
`;

/**
 * Plain JSON for an API path, as the site itself reads it.
 *
 * A captured envelope cannot be decoded on its own: the bundle exposes no function that
 * takes one, only the client that unwraps whatever it just received. So the request is
 * reissued rather than replayed - `path` and `params` are what the caller already has.
 *
 * Callers spell the path the way they spell a full URL (`/api/v1/manga/...`), but the
 * site's own client carries `/api/v1` in its baseURL and 404s if given the prefix too,
 * so it is stripped here rather than at every call site.
 */
export async function apiRequest(path, params = {}) {
  const apiPath = path.replace(/^\/api\/v1(?=\/|$)/, '') || '/';
  const run = async () => {
    await spendJarCall();
    try {
      const out = await evaluateWithin(
        (pair) => (0, eval)('(' + pair[0] + ')')(pair[1]),
        [REQUEST_VIA_CLIENT_JS, { path: apiPath, params }],
        SIGN_TIMEOUT_MS,
        'api request',
      );
      if (out && out.error) throw new Error(out.error);
      if (!out || typeof out.json !== 'string') throw new Error(`no body for ${path}`);
      return out.json;
    } catch (e) {
      // A spent jar answers by never settling, so treat any failure as a spent budget.
      jarCalls = API_CALLS_PER_JAR;
      throw e;
    }
  };
  const json = await withRetry('request', run);
  stats.decrypts++;
  return json;
}

export function oracleStats() {
  return { ...stats, ready };
}

/** Throws the page away and reads the live site again, for a redeploy under us. */
export async function rebuild() {
  await closeAll();
  stats.rebuilds++;
  return ensure();
}

export async function shutdown() {
  await closeAll();
}
