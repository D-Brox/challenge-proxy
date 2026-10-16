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
//
// The jar is the scarce resource. Cloudflare answers 502 for this API with
// `origin_bad_gateway` and `retry-after: 60` - comix.to's own origin failing - and a given
// session cookie gets roughly one origin-bound API call out of it before that starts. A
// spent jar never recovers: the same one was still dead a minute later. So every request
// here gets a freshly solved jar and a page built on it, and the page is discarded the
// moment that request is done. Responses Cloudflare can serve from its edge do not reach
// the origin, so a cache is what makes repeat browsing affordable.
import { chromium } from 'playwright';
import { acquireJar } from './waf.js';
import { log } from './log.js';

const BASE = process.env.COMIX_BASE || 'https://comix.to';
const READY_TIMEOUT_MS = Number(process.env.ORACLE_READY_TIMEOUT_MS || 45000);
const EVAL_TIMEOUT_MS = Number(process.env.ORACLE_EVAL_TIMEOUT_MS || 20000);
// Importing the bundle's module graph and waiting for the dispatch takes longer than a
// plain evaluation, so signing gets its own budget.
const SIGN_TIMEOUT_MS = Number(process.env.ORACLE_SIGN_TIMEOUT_MS || 45000);
const CAPTURE_TIMEOUT_MS = Number(process.env.ORACLE_CAPTURE_TIMEOUT_MS || 20000);
// A request that has not answered by now has failed, and the only fix is a fresh jar. A
// healthy call answers in a few hundred milliseconds, so this is generous.
const REQUEST_TIMEOUT_MS = Number(process.env.ORACLE_REQUEST_TIMEOUT_MS || 20000);
// Pages are cheap inside one browser, but a jar is not: FlareSolverr needs ~11s for one and
// the site only hands out an API call or two per jar. So this is a ceiling on how many
// requests can be in flight, not a pool to keep warm - a page built with nobody waiting for
// it would burn a jar on nothing. Pages are made on demand and thrown away after one call.
const POOL_SIZE = Number(process.env.ORACLE_POOL_SIZE || 4);
// Suwayomi asks for the same chapter lists repeatedly while a user browses, and a repeat
// costs a jar unless it is served from here. Anything Cloudflare can answer from its edge
// was never charged to the origin anyway, so this is mostly free.
const CACHE_TTL_MS = Number(process.env.ORACLE_CACHE_TTL_MS || 5 * 60 * 1000);
const CACHE_MAX = Number(process.env.ORACLE_CACHE_MAX || 500);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let browser = null;
let nextId = 1;
/** Live pages. Each was built on a jar that is good for the one request it is serving. */
const entries = [];
/** Builds in flight. Counted against the pool limit so concurrent callers cannot all decide
 *  there is room at the same moment. */
const building = [];
let jarCalls = 0;
const waiters = [];
const cache = new Map();
let cacheHits = 0;
let cacheMisses = 0;

const stats = {
  signs: 0, navigations: 0, decrypts: 0, rebuilds: 0, rotations: 0,
  readyAt: null, lastKind: null, pokeMisses: 0, permanent: 0,
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
        // comix.to's origin answering badly - "comix.to | 502: Bad gateway", with no scripts
        // at all. Waiting the full readiness timeout on one of these is 45s of nothing per
        // attempt, and it never resolves on its own.
        originDown: /502|bad gateway|service unavailable|error 5\d\d/i.test(document.title),
        url: location.href,
        title: document.title,
        scripts: scripts.length,
      };
    }, undefined, 15000, 'readiness probe').catch((e) => ({ error: String((e && e.message) || e) }));
    last = probe || {};
    if (last.ready) {
      entry.ready = true;
      stats.readyAt = Date.now() - started;
      log.info('oracle entry ready', { id: entry.id, ms: stats.readyAt });
      return true;
    }
    if (last.challenged) {
      log.warn('oracle entry was bounced to the security check', { id: entry.id, url: last.url, title: last.title });
      return false;
    }
    if (last.originDown) {
      log.warn('comix.to served an error page instead of the site', { id: entry.id, title: last.title });
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
 * A page is built for one request and thrown away after it, because the jar underneath is
 * good for about one call. Chromium stays up throughout: relaunching the browser per
 * request cost ~12s a time and dominated everything else.
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
    await closeEntry(entry);
    return false;
  }
  entries.push(entry);
  log.info('oracle entry ready', { id: entry.id, ms: stats.readyAt });
  return true;
}

/**
 * Builds one page, on a jar of its own.
 *
 * Only ever called when a request is actually waiting for one. A jar costs an ~11s
 * FlareSolverr solve and the site charges it against the origin, so building a page nobody
 * asked for would spend one of a scarce resource on nothing.
 */
async function buildEntry() {
  if (!browser) {
    browser = await chromium.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-dev-shm-usage'],
      ...(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {}),
    });
    log.info('browser up', { maxConcurrent: POOL_SIZE });
  }
  stats.rotations++;
  return openEntry(await acquireJar());
}

/** A page nobody is using, or null. */
function idleEntry() {
  return entries.find((e) => e.ready && !e.busy);
}

/**
 * Claims a page for one caller, building one if there is room and waiting if there is not.
 *
 * There is no queue in front of the builds: a request that arrives while four pages are
 * already in flight waits for one of those to finish, and then every page in the pool is
 * thrown away, so the wait is for a jar rather than for a page to be free.
 */
async function acquireEntry() {
  for (;;) {
    const free = idleEntry();
    if (free) {
      free.busy = true;
      return free;
    }
    if (entries.length + building.length < POOL_SIZE) {
      const build = buildEntry()
        .catch((e) => {
          log.warn('could not build an oracle entry', { error: String((e && e.message) || e) });
          return false;
        })
        .finally(() => {
          const i = building.indexOf(build);
          if (i !== -1) building.splice(i, 1);
        });
      building.push(build);
      // Not `continue`: fall through and take the page this build just produced.
      if (await build) continue;
      // Nothing came up. Back off instead of spinning on the same failure.
      await sleep(1000);
      continue;
    }
    await new Promise((resolve) => waiters.push(resolve));
  }
}

/**
 * Throws a page away once it has served its one request.
 *
 * The jar beneath it is spent either way - a successful call used the last of it, a failed
 * one means it was spent before we arrived - so nothing here is ever worth keeping, and
 * holding on to it is what shared one jar across the pool and made the first caller eat the
 * whole budget.
 */
function discardEntry(entry) {
  entry.busy = false;
  const i = entries.indexOf(entry);
  if (i !== -1) entries.splice(i, 1);
  closeEntry(entry).catch(() => {});
  const next = waiters.shift();
  if (next) next();
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

// Three, because each attempt costs a fresh ~11s solve, so the third is already a third of
// a minute of waiting and a fourth would be worse than failing.
const MAX_ATTEMPTS = Number(process.env.ORACLE_MAX_ATTEMPTS || 3);

/**
 * Errors that a fresh jar cannot fix, so spending one on them is waste.
 *
 * A 404 is the site's own answer about a path or a page that does not exist, and it will
 * still be true in a second. Everything else - 502, a timeout, a page that will not boot -
 * is the jar's fault, which a new jar does fix.
 */
function isPermanent(message) {
  return /\b404\b|\b400\b|\b422\b/.test(message);
}

/**
 * Runs `what` on a page of its own, on a jar of its own.
 *
 * There is no reload-first recovery any more, which used to be the plan: reloading the page
 * was cheaper than rotating the jar, and the two failures were thought to have different
 * causes. They do not. A spent jar stays spent - verified still dead after a minute - so a
 * reload only ever burned the readiness timeout against a page that could not work. Every
 * attempt now starts from a newly solved jar, which is the only thing that has ever
 * actually restored service.
 */
async function retryLoop(what, run) {
  let lastError;
  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    const entry = await acquireEntry();
    const outcome = await run(entry).then(
      (value) => ({ value }),
      (error) => ({ error }),
    );
    discardEntry(entry);
    if (!outcome.error) return outcome.value;
    lastError = outcome.error;

    const message = String((outcome.error && outcome.error.message) || outcome.error);
    if (isPermanent(message)) {
      stats.permanent++;
      log.warn(`${what} failed and will fail again`, { attempt: attempt + 1, error: message });
      throw outcome.error;
    }
    log.warn(`${what} failed`, { attempt: attempt + 1, of: MAX_ATTEMPTS, error: message });
    stats.rebuilds++;
  }
  log.error(`${what} failed on every attempt`, { attempts: MAX_ATTEMPTS });
  throw lastError;
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
/**
 * A stable key for a request, so `{"order":{"number":"desc"}}` and the same object built in
 * a different order are one cache entry rather than two.
 */
function cacheKey(apiPath, params) {
  const stable = (v) => {
    if (v === null || typeof v !== 'object') return JSON.stringify(v);
    if (Array.isArray(v)) return `[${v.map(stable).join(',')}]`;
    return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${stable(v[k])}`).join(',')}}`;
  };
  return `${apiPath}?${stable(params || {})}`;
}

export async function apiRequest(path, params = {}) {
  const apiPath = path.replace(/^\/api\/v1(?=\/|$)/, '') || '/';
  const key = cacheKey(apiPath, params);

  // Worth checking before anything expensive: a repeat costs a jar otherwise, and Suwayomi
  // repeats chapter lists every time a source is refreshed.
  const hit = cache.get(key);
  if (hit && Date.now() - hit.at < CACHE_TTL_MS) {
    cacheHits++;
    cache.delete(key);
    cache.set(key, hit);
    return hit.json;
  }
  cacheMisses++;

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

  if (cache.size >= CACHE_MAX) cache.delete(cache.keys().next().value);
  cache.set(key, { at: Date.now(), json });
  stats.decrypts++;
  return json;
}

export function oracleStats() {
  return {
    ...stats,
    ready: entries.length > 0 || building.length > 0,
    pool: entries.length,
    building: building.length,
    pages: entries.length,
    inUse: entries.filter((e) => e.busy).length,
    waiting: waiters.length,
    cache: { size: cache.size, hits: cacheHits, misses: cacheMisses, ttlMs: CACHE_TTL_MS },
  };
}

/** Throws the pool away and reads the live site again, for a redeploy under us. */
export async function rebuild() {
  stats.rebuilds++;
  const old = entries.splice(0, entries.length);
  await Promise.all(old.map(closeEntry));
  cache.clear();
  if (browser) {
    try { await browser.close(); } catch { /* already gone */ }
    browser = null;
  }
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
