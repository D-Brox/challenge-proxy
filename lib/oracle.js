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
import { getCfClearance, prewarmCookies } from './waf.js';
import { log } from './log.js';

const BASE = process.env.COMIX_BASE || 'https://comix.to';
const READY_TIMEOUT_MS = Number(process.env.ORACLE_READY_TIMEOUT_MS || 45000);
const EVAL_TIMEOUT_MS = Number(process.env.ORACLE_EVAL_TIMEOUT_MS || 20000);
// Importing the bundle's module graph and waiting for the dispatch takes longer than a
// plain evaluation, so signing gets its own budget.
const SIGN_TIMEOUT_MS = Number(process.env.ORACLE_SIGN_TIMEOUT_MS || 45000);
const CAPTURE_TIMEOUT_MS = Number(process.env.ORACLE_CAPTURE_TIMEOUT_MS || 20000);
// A spent cookie jar shows up as a call that never settles, so an API request that has not
// answered by now is treated as one and the jar is replaced. A healthy call answers in a
// few hundred milliseconds, so this is generous and only ever costs a rotation.
const REQUEST_TIMEOUT_MS = Number(process.env.ORACLE_REQUEST_TIMEOUT_MS || 20000);
// Pages are cheap inside one browser and each keeps its own copy of the site's state, so
// requests run several at a time instead of queueing behind one shared page. Measured: at
// 12 concurrent calls this is roughly 6x less wall time, and the site showed no sign of
// minding. Beyond four the browser process itself becomes the bottleneck, not the site.
const POOL_SIZE = Number(process.env.ORACLE_POOL_SIZE || 4);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let browser = null;
let nextId = 1;
/** Every live page, each holding the site's bundle and one shared cookie jar. */
const entries = [];
let building = null;
let jarCalls = 0;
const waiters = [];

const stats = {
  signs: 0, navigations: 0, decrypts: 0, rebuilds: 0, rotations: 0,
  readyAt: null, lastKind: null, pokeMisses: 0,
};

/**
 * Installed into every page before the site's own modules run.
 *
 * The API client is found here and cached, because readiness depends on it: the module
 * that exposes the client is the one that also owns the input counter, so a page that can
 * produce a client is a page whose input listener is attached. The keystroke counter is
 * what makes a silently-dropped poke visible in the logs instead of showing up later as
 * unexplained 502s.
 */
const PAGE_HELPERS = `
  window.__oracleApi = null;
  window.__oraclePokes = 0;
  window.addEventListener('keydown', function (e) {
    if (e.isTrusted) window.__oraclePokes++;
  }, true);
  window.__oracleFindApi = async function () {
    if (window.__oracleApi) return true;
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
        window.__oracleApi = { api: value, key: get[0] };
        return true;
      }
    }
    return false;
  };
`;

/**
 * page.evaluate has no timeout of its own, so a busy main thread would hang forever.
 * It also forwards exactly one argument, so anything the page side needs travels as a
 * single value.
 */
async function evaluateWithin(entry, fn, arg, ms, label) {
  let timer;
  try {
    return await Promise.race([
      entry.page.evaluate(fn, arg),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function closeEntry(entry) {
  for (const closer of [entry.page, entry.context]) {
    try {
      if (closer) await closer.close();
    } catch { /* already gone */ }
  }
}

/** Takes a page out of rotation before closing it, so nothing hands it out meanwhile. */
async function dropEntry(entry) {
  const i = entries.indexOf(entry);
  if (i !== -1) entries.splice(i, 1);
  await closeEntry(entry);
}

/** Waits until the bundle has booted and the site's own API client can be reached. */
async function waitReady(entry) {
  entry.ready = false;
  const started = Date.now();
  const deadline = Date.now() + READY_TIMEOUT_MS;
  let last = {};
  while (Date.now() < deadline) {
    const probe = await evaluateWithin(entry, async () => {
      const scripts = performance.getEntriesByType('resource').map((e) => e.name)
        .filter((u) => /\/assets\/.*\.js$/.test(u));
      return {
        // Ready means the site's own API client answered, not merely that its bundle
        // finished downloading. The two can differ for seconds, and a request sent in
        // between goes out unsigned - which is far harder to diagnose than a slow boot.
        ready: await window.__oracleFindApi(),
        // A jar the site no longer trusts bounces the page to its challenge instead of
        // loading the bundle, so there is nothing to wait for.
        challenged: /\/@waf|challenge|just a moment/i.test(`${location.pathname} ${document.title}`),
        url: location.href,
        title: document.title,
        scripts: scripts.length,
      };
    }, undefined, 15000, 'readiness probe').catch((e) => ({ error: String((e && e.message) || e) }));
    last = probe || {};
    if (last.ready) {
      entry.ready = true;
      stats.readyAt = Date.now() - started;
      log.info('oracle entry ready', { id: entry.id, ms: stats.readyAt, pool: entries.length + 1 });
      return true;
    }
    if (last.challenged) {
      log.warn('oracle entry was bounced to the security check', { id: entry.id, url: last.url, title: last.title });
      return false;
    }
    await sleep(500);
  }
  log.error('oracle entry never became ready', { id: entry.id, waitedMs: READY_TIMEOUT_MS, ...last });
  return false;
}

/**
 * Opens a context and page carrying [cf]'s cookies and waits for the bundle to boot.
 *
 * Split out because a fresh jar is needed constantly - the site's per-jar API budget is
 * only a couple of calls - and swapping cookies does not need a new browser process.
 * Relaunching Chromium per rotation cost ~12s a time and dominated every request.
 */
async function openEntry(cf) {
  const context = await browser.newContext({ userAgent: cf.userAgent });
  await context.addInitScript(PAGE_HELPERS);
  // The whole jar: without `session` alongside cf_clearance the page never boots.
  await context.addCookies(cf.cookies.map((c) => ({
    name: c.name,
    value: c.value,
    domain: c.domain,
    path: c.path || '/',
  })));
  const entry = { id: nextId++, context, page: await context.newPage(), ready: false, busy: false };
  await entry.page.goto(`${BASE}/browse`, { waitUntil: 'domcontentloaded', timeout: 90000 }).catch(() => {});
  if (!(await waitReady(entry))) {
    await dropEntry(entry);
    return false;
  }
  entries.push(entry);
  // Only once a rotation has actually been needed. Holding the site's flag down means it
  // rarely is, and each solve costs FlareSolverr ~11s of browser time.
  if (stats.rotations > 0) prewarmCookies();
  return true;
}

/** Tops the pool up to POOL_SIZE on the given jar. Boots in parallel; they are independent. */
async function fillPool(cf) {
  const wanted = POOL_SIZE - entries.length;
  if (wanted <= 0) return;
  const built = await Promise.all(Array.from({ length: wanted }, () => openEntry(cf).catch((e) => {
    log.warn('an oracle entry failed to boot', { error: String((e && e.message) || e) });
    return false;
  })));
  return built.some(Boolean);
}

/** Brings the pool up, sharing one build between concurrent callers. */
async function ensurePool() {
  if (entries.length >= POOL_SIZE && entries.some((e) => e.ready)) return;
  if (!building) {
    building = (async () => {
      const cf = await getCfClearance();
      if (!browser) {
        browser = await chromium.launch({
          headless: true,
          args: ['--no-sandbox', '--disable-dev-shm-usage'],
          ...(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {}),
        });
        log.info('browser up', { pool: POOL_SIZE });
      }
      await fillPool(cf);
    })().finally(() => { building = null; });
  }
  await building;
  if (!entries.some((e) => e.ready)) {
    // Nothing booted. A jar the site no longer trusts bounces the page to its challenge
    // rather than loading the bundle, so no amount of retrying on it will help: solve a
    // fresh one and go round again.
    log.warn('no oracle entry came up, re-solving cookies');
    stats.rotations++;
    jarCalls = 0;
    const cf = await getCfClearance(true).catch((e) => {
      log.error('could not re-solve cookies', { error: String((e && e.message) || e) });
      return null;
    });
    if (cf) {
      const old = entries.splice(0, entries.length);
      await Promise.all(old.map(closeEntry));
      await fillPool(cf);
    }
  }
}

/** A page nobody is using, or null. */
function idleEntry() {
  return entries.find((e) => e.ready && !e.busy && !e.stale);
}

/**
 * Claims a page for one caller, waiting if they are all busy.
 *
 * Serialising globally is what the single-page design needed, and it is the wrong shape
 * for a pool: N simultaneous callers cost N times one request. Here the only limit is
 * that a page serves one caller at a time, which is what keeps a reload from tearing the
 * page out from under an in-flight evaluate.
 */
async function acquireEntry() {
  for (;;) {
    await ensurePool();
    const free = idleEntry();
    if (free) {
      free.busy = true;
      return free;
    }
    await new Promise((resolve) => waiters.push(resolve));
  }
}

function releaseEntry(entry) {
  entry.busy = false;
  if (entry.stale) {
    // The jar was rotated while this page was in use. Drop it now that the caller is done,
    // rather than closing it mid-evaluate and failing the request for no real reason.
    const i = entries.indexOf(entry);
    if (i !== -1) entries.splice(i, 1);
    closeEntry(entry).catch(() => {});
    ensurePool().catch(() => {});
  }
  const next = waiters.shift();
  if (next) next();
}

/**
 * Replaces every page in the pool on a freshly solved jar.
 *
 * Only idle pages are closed outright. A page another request is still using is flagged
 * instead and dropped the moment its caller releases it - closing it here is exactly the
 * "Cannot read properties of null (reading 'evaluate')" failure the old global queue
 * existed to prevent, and with several pages in flight it would be far easier to hit.
 */
async function rotateJar() {
  stats.rotations++;
  jarCalls = 0;
  const cf = await getCfClearance(true);
  log.info('rotating the jar across the pool', { used: jarCalls, pool: entries.length });
  const replaceable = [];
  for (const entry of entries) {
    if (entry.busy) entry.stale = true;
    else replaceable.push(entry);
  }
  for (const entry of replaceable) {
    const i = entries.indexOf(entry);
    if (i !== -1) entries.splice(i, 1);
  }
  await Promise.all(replaceable.map(closeEntry));
  await fillPool(cf);
}

/**
 * Gives the page the user input it insists on.
 *
 * The site's own client watches for trusted click/pointerdown/keydown events. If a chapter
 * list is fetched three times with none in the last 2s, it raises a flag of its own accord,
 * adds v=1 to every chapter request from then on, and the server answers 502 for the rest of
 * the page's life - there is no way back but a reload. A keypress is enough to hold the flag
 * down, and costs microseconds next to rotating a cookie jar.
 *
 * A wheel scroll is deliberately not used: the bundle listens for click, pointerdown and
 * keydown only, and a scroll leaves the flag set.
 *
 * The counter on the page is read back afterwards. A poke that quietly stops working is
 * indistinguishable from a rate limit until the 502s start arriving, which is far too late
 * to connect the two, so it is worth two round trips to notice.
 */
async function pokeUserInput(entry) {
  const read = () => evaluateWithin(entry, () => window.__oraclePokes || 0, undefined, 5000, 'poke read')
    .catch(() => null);
  const before = await read();
  try {
    await entry.page.keyboard.press('Shift');
  } catch (e) {
    stats.pokeMisses++;
    log.warn('could not deliver input to the page', { id: entry.id, error: String((e && e.message) || e) });
    return;
  }
  const after = await read();
  if (before !== null && after !== null && after <= before) {
    stats.pokeMisses++;
    log.warn('the page never saw the keystroke', { id: entry.id, before, after });
  }
}

// Three, because the first failure costs only a page reload and the second a fresh jar.
const MAX_ATTEMPTS = Number(process.env.ORACLE_MAX_ATTEMPTS || 3);

async function retryLoop(what, run) {
  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    const entry = await acquireEntry();
    // Settled rather than thrown, because every path below has to hand the page back and
    // returning early from a try is exactly how it ends up leaked - which strands the
    // request and, once the pool is empty, every request behind it.
    const outcome = await run(entry).then(
      (value) => ({ value }),
      (error) => ({ error }),
    );

    if (!outcome.error) {
      releaseEntry(entry);
      return outcome.value;
    }

    const message = String((outcome.error && outcome.error.message) || outcome.error);
    if (attempt === MAX_ATTEMPTS - 1) {
      releaseEntry(entry);
      log.error(`${what} failed on every attempt`, { attempts: MAX_ATTEMPTS, error: message });
      throw outcome.error;
    }

    stats.rebuilds++;
    // The two failures have different causes, and recovering them in the wrong order is
    // what used to wedge this: a reload cannot fix a dead jar, and a new jar cannot fix a
    // flag living in this page's JavaScript.
    if (attempt === 0) {
      log.warn(`${what} failed, reloading the page`, { attempt: 1, of: MAX_ATTEMPTS, id: entry.id, error: message });
      await entry.page.reload({ waitUntil: 'domcontentloaded', timeout: 90000 }).catch(() => {});
      if (!(await waitReady(entry))) await dropEntry(entry);
      releaseEntry(entry);
    } else {
      log.warn(`${what} failed again, rotating the jar`, { attempt: attempt + 1, of: MAX_ATTEMPTS, error: message });
      releaseEntry(entry);
      await rotateJar();
    }
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
async function signViaBrowse(entry, path, params) {
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
  entry.page.on('request', listener);

  const browseParams = { ...params, order: params.order };
  await entry.page.goto(`${BASE}/browse${query ? `?${query}` : ''}`, {
    waitUntil: 'domcontentloaded',
    timeout: 90000,
  }).catch(() => {});

  const deadline = Date.now() + CAPTURE_TIMEOUT_MS;
  while (Date.now() < deadline && !captured.length) await sleep(250);
  entry.page.off('request', listener);
  stats.navigations++;
  return captured[0] || null;
}

/**
 * A fully signed URL for `path` with `params`, exactly as the site would send it.
 * Throws when no signed URL could be produced.
 */
export async function signedUrl(path, params = {}) {
  const run = async (entry) => {
    jarCalls++;
    await pokeUserInput(entry);
    // Playwright forwards one argument and never a string body, so the page-side source
    // travels as data and is instantiated there.
    const viaRoute = await evaluateWithin(
      entry,
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
      const url = await signViaBrowse(entry, path, params);
      if (url) {
        stats.lastKind = 'browse';
        return url;
      }
    }
    throw new Error(`could not sign ${path}: ${viaRoute?.error || 'no request was made'}`);
  };
  const url = await retryLoop('sign', run);
  stats.signs++;
  return url;
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
 * Nothing here names a minified symbol: the client module was picked by the shape of its
 * exports (an object whose members are all functions, one of which wraps the axios GET) and
 * cached on the page by PAGE_HELPERS, so the route survives a redeploy.
 */
const REQUEST_VIA_CLIENT_JS = `
async function (spec) {
  if (!window.__oracleApi && !(await window.__oracleFindApi())) {
    return { error: 'the bundle exposes no api client' };
  }
  try {
    var data = await window.__oracleApi.api[window.__oracleApi.key](
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
  const run = async (entry) => {
    jarCalls++;
    await pokeUserInput(entry);
    const out = await evaluateWithin(
      entry,
      (pair) => (0, eval)('(' + pair[0] + ')')(pair[1]),
      [REQUEST_VIA_CLIENT_JS, { path: apiPath, params }],
      REQUEST_TIMEOUT_MS,
      'api request',
    );
    if (out && out.error) throw new Error(out.error);
    if (!out || typeof out.json !== 'string') throw new Error(`no body for ${path}`);
    return out.json;
  };
  const json = await retryLoop('request', run);
  stats.decrypts++;
  return json;
}

export function oracleStats() {
  return {
    ...stats,
    ready: entries.some((e) => e.ready && !e.stale),
    pool: entries.filter((e) => e.ready && !e.stale).length,
    pages: entries.length,
    inUse: entries.filter((e) => e.busy).length,
    waiting: waiters.length,
  };
}

/** Throws the pool away and reads the live site again, for a redeploy under us. */
export async function rebuild() {
  stats.rebuilds++;
  const old = entries.splice(0, entries.length);
  await Promise.all(old.map(closeEntry));
  if (browser) {
    try { await browser.close(); } catch { /* already gone */ }
    browser = null;
  }
  await ensurePool();
  return oracleStats().ready;
}

export async function shutdown() {
  const old = entries.splice(0, entries.length);
  await Promise.all(old.map(closeEntry));
  if (browser) {
    try { await browser.close(); } catch { /* already gone */ }
    browser = null;
  }
}
