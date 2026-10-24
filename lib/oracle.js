// Crypto oracle: a long-lived headless Chromium that keeps the site's own bundle
// loaded so requests can be run through it.
//
// The bundle re-obfuscates on every deploy and its API has changed shape with the
// `tnb2e5` build: the old `/api/v1` pass-through client is gone. What remains for data
// are route-store members - hidden functions that build, sign, send and *map* each API
// response into the site's own view models (obfuscated keys). So the request lives here:
//
//   * Each of the three API paths the extension needs maps to one store member, found by
//     probing every hidden member of the site's chunks with an impossible id and reading
//     which request the member was about to send:
//       /api/v1/manga                    -> listing member      `es(params)`
//       /api/v1/manga/<mangaId>/chapters -> chapter-list member  `xj(id, params)`
//       /api/v1/chapters/<chapterId>     -> chapter member       `Ae(chapterId)`
//   * Calling the member returns the *mapped* view data, not the wire JSON. The key
//     remapping it applied is described by `lib/mapper-registry.json` (a reverse of the
//     site's mappers, extracted from the bundle with .scratch/map-extract.py); the page
//     side applies the registry backwards and reshapes into the three response bodies the
//     extension parses (SearchResponse, ChapterDetailsResponse, ChapterResponse).
//
// Nothing depends on a minified name: the store members are found by behavior, and the
// registry only carries mangled keys that must change with a redeploy (a stale registry
// fails loudly instead of serving half-mapped data).
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
import { readFileSync, writeFileSync, renameSync, unlinkSync } from 'node:fs';
import { extractRegistry } from './heal.mjs';
import { fileURLToPath } from 'node:url';

const BASE = process.env.COMIX_BASE || 'https://comix.to';
// The first finder pass after a redeploy has to walk every hidden member of the site's
// chunks, and that walk is slow (~91s in the Oct 19 build). One cold pass is expected, so
// this bounds it; once the first pass succeeds the route hints are saved and later entries
// verify them with a handful of probes.
const READY_TIMEOUT_MS = Number(process.env.ORACLE_READY_TIMEOUT_MS || 180000);
// Importing the bundle's module graph and waiting for the dispatch takes longer than a
// plain evaluation, so store calls get their own budget.
const SIGN_TIMEOUT_MS = Number(process.env.ORACLE_SIGN_TIMEOUT_MS || 45000);
const EVAL_TIMEOUT_MS = Number(process.env.ORACLE_EVAL_TIMEOUT_MS || 20000);
// A request that has not answered by now has failed, and the only fix is a fresh jar. A
// healthy call answers in a few hundred milliseconds, so this is generous.
const REQUEST_TIMEOUT_MS = Number(process.env.ORACLE_REQUEST_TIMEOUT_MS || 20000);
// Pages are cheap inside one browser, but a jar is not: FlareSolverr needs ~11s for one and
// the site only hands out an API call or two per jar. So this is a ceiling on how many
// requests can be in flight, not a pool to keep warm - a page built with nobody waiting for
// it would burn a jar on nothing. Pages are made on demand and thrown away after one call.
const POOL_SIZE = Number(process.env.ORACLE_POOL_SIZE || 4);
// How many requests one jar is allowed to serve before being replaced anyway.
//
// The site's per-cookie allowance is not a constant - measured today at 1 call, then at 2-34,
// then at 45+ on the same code - so a jar is kept until it actually fails rather than
// budgeted against a number that moves. This cap only stops one entry from outliving its
// clearance by an hour, and gives the pool a slow turnover so a redeploy is picked up.
const REUSE_MAX = Number(process.env.ORACLE_REUSE_MAX || 50);
// Suwayomi asks for the same chapter lists repeatedly while a user browses, and every repeat
// costs a jar unless it is served from here. Measured: 37% of requests were repeats that a
// 5-minute window missed, because navigating back to a title takes minutes. Fifteen minutes
// catches those, and a chapter list only changes when the site uploads one - a new entry at
// the top of a list ordered by number desc.
const CACHE_TTL_MS = Number(process.env.ORACLE_CACHE_TTL_MS || 15 * 60 * 1000);
const CACHE_MAX = Number(process.env.ORACLE_CACHE_MAX || 2000);

/**
 * The reverse mapper registry, extracted from the current bundle by
 * .scratch/map-extract.py. Everything mangled inside changes on a redeploy - a registry
 * that does not match the served build fails the unmangle loudly (see the flatten sig
 * check) instead of answering with garbage. `lib/heal.mjs` re-extracts it automatically.
 */
const REGISTRY_PATH = process.env.COMIX_MAPPER_REGISTRY
  || new URL('./mapper-registry.json', import.meta.url).pathname;
let mappers = null;
export function loadRegistry(force = false) {
  if (mappers && !force) return mappers;
  try {
    const raw = JSON.parse(readFileSync(REGISTRY_PATH, 'utf8'));
    if (!raw || typeof raw !== 'object' || !raw.mappers || !raw.roles) throw new Error('missing mappers/roles');
    mappers = raw;
    return mappers;
  } catch (e) {
    log.error('mapper registry unavailable - copy lib/mapper-registry.json beside this file', {
      path: REGISTRY_PATH, error: String((e && e.message) || e),
    });
    return null;
  }
}

// Last verified store member references ({chunk, exportName, key} per role), shared by
// every entry instead of re-scanned per request page. Kept next to the jar store so a
// process restart keeps it. Versioned: hints without the value are ignored.
const HINT_FILE = `${process.env.WAF_JAR_STORE || '/app/.jars'}/oracle-routes.json`;
const HINT_VERSION = 'store-routes-2';
let routeHint = null;
try {
  const saved = JSON.parse(readFileSync(HINT_FILE, 'utf8'));
  if (saved && saved.ver === HINT_VERSION && saved.routes) routeHint = saved;
} catch { /* no hint saved yet */ }

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
  decrypts: 0, rebuilds: 0, rotations: 0,
  readyAt: null, pokeMisses: 0, permanent: 0, abandoned: 0,
  reused: 0, rotatedOut: 0, heals: 0, healFails: 0, lastHeal: null,
};

/**
 * Installed into every page before the site's own modules run.
 *
 * The three store members are found here and cached, because readiness depends on them:
 * a page that can call a route member is a page whose bundle booted fully. The keystroke
 * counter is what makes a silently-dropped poke visible in the logs instead of showing up
 * later as unexplained 502s.
 *
 * The mappers registry travels as a plain constant - it is data, not code, and it is
 * applied *backwards*: the site's own mappers turn wire JSON into view objects on the
 * way in, and this maps the view keys back to what the extension parses on the way out.
 */
const PAGE_HELPERS = `
  window.__oracleRoutes = null;
  window.__oracleHintInfo = null;
  window.__oraclePokes = 0;
  window.addEventListener('keydown', function (e) {
    if (e.isTrusted) window.__oraclePokes++;
  }, true);
  window.__oracleHttp = { method: null, url: null };
  var xhrOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (m) {
    window.__oracleHttp = { method: m, url: arguments[1] };
    return xhrOpen.apply(this, arguments);
  };
  var siteFetch = window.fetch;
  window.fetch = function (input) {
    window.__oracleHttp = { method: (input && input.method) || 'GET', url: typeof input === 'string' ? input : input && input.url };
    return siteFetch.apply(this, arguments);
  };
  var assetUrls = function () {
    var found = performance.getEntriesByType('resource').map(function (e) { return e.name; })
      .filter(function (u) { return /\\/assets\\/.*\\.js$/.test(u); });
    for (var s of document.querySelectorAll('script[type="module"]')) if (s.src) found.push(s.src);
    return Array.from(new Set(found));
  };
  // Calls a candidate store member with an id that cannot exist and returns the request it
  // was about to send. The id is interpolated verbatim into the member's own template, so
  // the captured path shows which API shape the member serves.
  window.__oracleProbe = async function (fn) {
    window.__oracleHttp = { method: null, url: null };
    try {
      await Promise.race([
        Promise.resolve().then(function () { return fn('zzconvmz'); }).catch(function () {}),
        new Promise(function (r) { setTimeout(r, 3000); }),
      ]);
    } catch (e) { /* the impossible id exists to make this cheap */ }
    return window.__oracleHttp || { method: null, url: null };
  };
  // Which of the three roles a captured request belongs to. Shape, not name: any member
  // that fits a template matches one role and only one.
  window.__oracleRoleOf = function (seen) {
    if (!seen || seen.method !== 'GET') return null;
    var u = String(seen.url || '');
    if (u.indexOf('/api/v1') !== 0) return null;
    var p = u.split('?')[0];
    if (p === '/api/v1/manga') return 'list';
    if (new RegExp('^\\/api\\/v1\\/manga\\/[^/]+\\/chapters$').test(p)) return 'chapters';
    if (new RegExp('^\\/api\\/v1\\/chapters\\/[^/]+$').test(p)) return 'pages';
    return null;
  };
  // Route member finder: tries saved references first, then walks every hidden member of
  // the site's chunks. The stores are Proxies with an ownKeys trap, so members are reached
  // by probing one- and two-character names. Matching is on the request shape, so a
  // redeploy is absorbed by the walk rather than by a name.
  var liveAssets = assetUrls();
  window.__oracleFind = async function (hint) {
    var roles = window.__oracleRoutes || {};
    var load = async function (ref, role) {
      if (!ref || !ref.chunk || !ref.key) return false;
      // Assets survive a redeploy on the CDN, so a hint saved for a previous build still
      // imports cleanly - and its member runs the OLD bundled client, which stamps tokens
      // the served API no longer accepts (403 missing_token). A hint is only trusted when
      // its chunk is one this very page actually loaded.
      if (liveAssets.indexOf(ref.chunk) === -1) return false;
      var mod;
      try { mod = await import(ref.chunk); } catch (e) { return false; }
      var holders = typeof ref.exportName === 'string' && ref.exportName in mod
        ? [mod[ref.exportName]]
        : Object.values(mod);
      for (var holder of holders) {
        if (!holder || typeof holder !== 'object' || Array.isArray(holder)) continue;
        var fn;
        try { fn = holder[ref.key]; } catch (e) { continue; }
        if (typeof fn !== 'function') continue;
        var seen = await window.__oracleProbe(fn, 'zzconvmz');
        if (window.__oracleRoleOf(seen) === role) {
          roles[role] = Object.assign({ role: role, chunk: ref.chunk, exportName: ref.exportName != null ? ref.exportName : null, key: ref.key }, { fn: fn, seen: String(seen.url) });
          return true;
        }
      }
      return false;
    };
    if (hint && hint.routes) {
      for (var role of ['list', 'chapters', 'pages']) {
        if (!roles[role]) await load(hint.routes[role], role);
      }
    }
    // The stores wrap their members in a Proxy whose ownKeys trap hides everything, so
    // entries/values are empty and membership cannot be enumerated. The get trap forwards
    // any name purely, so probing every one- and two-character identifier finds the
    // members.
    var chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$';
    var missing = function () {
      return ['list', 'chapters', 'pages'].filter(function (r) { return !roles[r]; });
    };
    if (missing().length) {
      for (var url of assetUrls()) {
        var mod;
        try { mod = await import(url); } catch (e) { continue; }
        for (var pair of Object.entries(mod)) {
          var value = pair[1];
          if (!value || typeof value !== 'object' || Array.isArray(value)) continue;
          var names = Object.entries(value).filter(function (p) { return typeof p[1] === 'function'; })
            .map(function (p) { return p[0]; });
          if (names.length < 2) {
            for (var i = 0; i < chars.length; i++) {
              var a = chars[i];
              if (typeof value[a] === 'function') names.push(a);
              for (var j = 0; j < chars.length; j++) {
                var ab = a + chars[j];
                if (typeof value[ab] === 'function') names.push(ab);
              }
            }
          }
          for (var n of names) {
            var fn = value[n];
            if (typeof fn !== 'function') continue;
            var wants = missing();
            if (!wants.length) break;
            var seen = await window.__oracleProbe(fn, 'zzconvmz');
            var role = window.__oracleRoleOf(seen);
            if (role && wants.indexOf(role) !== -1) {
              roles[role] = { role: role, chunk: url, exportName: pair[0], key: n, fn: fn, seen: String(seen.url) };
            }
          }
          if (!missing().length) break;
        }
        if (!missing().length) break;
      }
    }
    var plain = {};
    for (var r of ['list', 'chapters', 'pages']) {
      if (roles[r]) plain[r] = { chunk: roles[r].chunk, exportName: roles[r].exportName, key: roles[r].key, url: roles[r].seen };
    }
    window.__oracleRoutes = roles;
    window.__oracleHintInfo = { ver: 'store-routes-2', routes: plain };
    return ['list', 'chapters', 'pages'].every(function (r) { return roles[r]; });
  };
  // The reverse mapper: applies the extracted registry to raw store output so the oracle
  // hands the extension the same plain shapes the old /api/v1 pass-through served. The
  // sig check up front is what makes a stale registry fail loudly instead of serving
  // half-mapped data - and what tells the self-heal a re-extraction is due.
  window.__oracleFlatten = function (role, raw) {
    var reg = window.__oracleRegistry;
    var rname = reg && reg.roles && reg.roles[role];
    var r = rname && reg.mappers[rname];
    if (!r) return { error: 'registry has no mapper for ' + role };
    var keys = Object.keys(r.entries);
    for (var k of keys) {
      if (!(k in raw)) return { error: 'registry does not match the served build', missing: k, got: Object.keys(raw).slice(0, 24) };
    }
    var applyEntries = function (obj, entries, depth) {
      if (depth > 8 || obj === null || typeof obj !== 'object' || Array.isArray(obj)) return obj;
      var o = {};
      for (var outKey of Object.keys(entries)) {
        var spec = entries[outKey];
        var v = obj[outKey];
        try {
          if (spec.k === 'prop' || spec.k === 'concat') o[spec.n] = v;
          else if (spec.k === 'child') o[spec.path] = unm(v, spec.name, depth + 1);
          else if (spec.k === 'list') o[spec.path] = unm(v, spec.child, depth + 1);
          else if (spec.k === 'cond') o[spec.path] = v && typeof v === 'object' ? applyEntries(v, spec.entries || {}, depth + 1) : v;
          else o[outKey] = v;
        } catch (e) { o[outKey] = v; }
      }
      return o;
    };
    var unm = function (v, name, depth) {
      var r = reg.mappers[name];
      if (depth > 8 || v === null || typeof v !== 'object' || !r) return v;
      if (r.listElement) {
        if (Array.isArray(v)) return v.map(function (x) { return unm(x, r.listElement, depth + 1); });
        return unm(v, r.listElement, depth + 1);
      }
      if (Array.isArray(v)) return v.every(function (x) { return x && typeof x === 'object' && !Array.isArray(x); })
        ? v.map(function (x) { return applyEntries(x, r.entries, depth + 1); })
        : applyEntries(v, r.entries, depth);
      return applyEntries(v, r.entries, depth);
    };
    var out = unm(raw, rname, 0);
    if (role === 'pages') {
      // Extension shape: ChapterResponse { pages: { baseUrl, items: [{url, s}], alt, node } }.
      // The store flattens each item's url (baseUrl + url) and carries alt/node on every
      // row, so the container is rebuilt from the first row.
      var rows = Array.isArray(out.pages) ? out.pages : [];
      return JSON.stringify({
        pages: {
          baseUrl: '',
          items: rows.map(function (x) { return { url: x.url, s: 0 }; }),
          alt: rows.length && rows[0].alt ? rows[0].alt : null,
          node: rows.length && rows[0].node ? rows[0].node : null,
        },
      });
    }
    return JSON.stringify(out);
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

/** Waits until the bundle has booted and all three store members can be reached. */
async function waitReady(entry) {
  entry.ready = false;
  const started = Date.now();
  const deadline = Date.now() + READY_TIMEOUT_MS;
  let last = {};
  while (Date.now() < deadline) {
    const probe = await evaluateWithin(entry, async (hint) => {
      const scripts = performance.getEntriesByType('resource').map((e) => e.name)
        .filter((u) => /\/assets\/.*\.js$/.test(u));
      return {
        // Ready means each of the three route-store members answered its probe, not merely
        // that the bundle finished downloading. The two can differ for seconds, and a
        // request sent in between goes out unsigned - which is far harder to diagnose than
        // a slow boot.
        ready: await window.__oracleFind(hint),
        // A jar the site no longer trusts bounces the page to its challenge instead of
        // loading the bundle, so there is nothing to wait for.
        challenged: /\/@waf|challenge|just a moment/i.test(`${location.pathname} ${document.title}`),
        // comix.to's origin answering badly - "comix.to | 502: Bad gateway", with no scripts
        // at all. Waiting the full readiness timeout on one of these is 45s of nothing per
        // attempt, and it never resolves on its own.
        originDown: /502|bad gateway|service unavailable|error 5\d\d/i.test(document.title),
        hint: window.__oracleHintInfo || null,
        url: location.href,
        title: document.title,
        scripts: scripts.length,
      };
    }, routeHint, READY_TIMEOUT_MS, 'readiness probe').catch((e) => ({ error: String((e && e.message) || e) }));
    last = probe || {};
    if (last.ready) {
      entry.ready = true;
      const hint = last.hint;
      if (hint && hint.routes && Object.keys(hint.routes).length === 3 &&
          (!routeHint || JSON.stringify(routeHint.routes) !== JSON.stringify(hint.routes))) {
        routeHint = hint;
        try { writeFileSync(HINT_FILE, JSON.stringify(routeHint)); } catch { /* jar store outages have been survivable elsewhere */ }
        log.info('oracle route hints updated', Object.entries(hint.routes)
          .map(([r, ref]) => `${r}=${ref.key}`).join(' '));
      }
      stats.readyAt = Date.now() - started;
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
  // The mappers registry is data, and the same one applies for the context's lifetime;
  // loading it on the host and injecting it here beats re-reading per evaluate.
  const registry = loadRegistry();
  if (registry) {
    await context.addInitScript(`window.__oracleRegistry = ${JSON.stringify(registry)};`);
  }
  if (routeHint) {
    await context.addInitScript(`window.__oracleHintRoutes = ${JSON.stringify(routeHint)};`);
  }
  // The whole jar: without `session` alongside cf_clearance the page never boots.
  await context.addCookies(cf.cookies.map((c) => ({
    name: c.name,
    value: c.value,
    domain: c.domain,
    path: c.path || '/',
  })));
  const entry = { id: nextId++, context, page: await context.newPage(), ready: false, busy: false, served: 0 };
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
async function buildEntry(signal) {
  if (!browser) {
    browser = await chromium.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-dev-shm-usage'],
      ...(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {}),
    });
    log.info('browser up', { maxConcurrent: POOL_SIZE });
  }
  // Checked here as well as at the call site: a build takes ~100ms, which is long enough for
  // the caller to give up in the middle of it, and the jar is the scarce part.
  if (signal?.aborted) throw abandoned();
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
async function acquireEntry(signal) {
  for (;;) {
    if (signal?.aborted) throw abandoned();
    const free = idleEntry();
    if (free) {
      free.busy = true;
      return free;
    }
    if (entries.length + building.length < POOL_SIZE) {
      const build = buildEntry(signal)
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
    // Every page is busy. Wait for one, but wake up if the caller leaves rather than sitting
    // here holding a slot that will never be used.
    await Promise.race([
      new Promise((resolve) => waiters.push(resolve)),
      signal?.aborted ? new Promise((_, reject) => signal.addEventListener('abort', () => reject(abandoned()), { once: true })) : null,
    ].filter(Boolean));
  }
}

/**
 * Throws a page - and the jar under it - away.
 *
 * Used when the last request failed, so the retry starts on a fresh jar. Callers only reach
 * here for a page they already own; closing one another request is using is the failure the
 * old global queue existed to prevent.
 */
function discardEntry(entry) {
  const i = entries.indexOf(entry);
  if (i !== -1) entries.splice(i, 1);
  closeEntry(entry).catch(() => {});
  const next = waiters.shift();
  if (next) next();
}

/**
 * Hands a page back for the next request, keeping its jar.
 *
 * This is what keeps FlareSolverr off the critical path: a jar that answered is evidence it
 * still has allowance, so it is kept until it stops answering rather than spent on a guess
 * about a number that moves.
 */
function releaseEntry(entry) {
  entry.served++;
  if (entry.served > 1) stats.reused++;
  if (entry.served >= REUSE_MAX) {
    stats.rotatedOut++;
    discardEntry(entry);
    return;
  }
  entry.busy = false;
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
 * still be true in a second. A stale registry normally never reaches here - its request
 * waits for the heal and retries (see the healWait branch below) - so a registry error
 * arriving here means no heal was available (cooldown, standing down) and burning jars
 * on retries would not change that. Everything else - 502, a timeout, a page that will
 * not boot - is the jar's fault, which a new jar does fix.
 */
function isPermanent(message) {
  return /\b404\b|\b400\b|\b422\b|registry/.test(message);
}

// ---------------------------------------------------------------- self-heal

// How often a re-extraction may be attempted, and how many failures in an hour are
// tolerated before the heal stands down (a structurally-changed bundle needs eyes; a
// looping healer would burn a jar per round for nothing).
const HEAL_COOLDOWN_MS = Number(process.env.ORACLE_HEAL_COOLDOWN_MS || 120000);
const HEAL_MAX_FAILS_PER_HOUR = Number(process.env.ORACLE_HEAL_MAX || 5);
// Min spacing between forced deploy recoveries: a recovery closes the browser and the
// entry pool, so a run of non-deploy 403s (dead jars, a WAF mood) must not rebuild the
// world on every attempt.
const DEPLOY_RECOVERY_COOLDOWN_MS = Number(process.env.ORACLE_DEPLOY_COOLDOWN_MS || 300000);
// How long a request that hit a stale registry waits for the heal it just triggered
// before giving up. The heal itself is seconds (one entry, one chunk fetch, three
// probes); this only has to cover the worst case, a cold pool on top of it.
const HEAL_WAIT_TIMEOUT_MS = Number(process.env.ORACLE_HEAL_WAIT_TIMEOUT_MS || 45000);
// How long a request that hit a deploy-signature 403 waits for the recovery it triggered
// (hint flush + browser rebuild). A fresh entry boot is a jar (~11s) plus page load.
const DEPLOY_RECOVERY_WAIT_MS = Number(process.env.ORACLE_DEPLOY_WAIT_MS || 45000);
const healState = { running: false, lastAt: 0, fails: [], promise: null, lastSuccessAt: 0 };

/**
 * Starts (or joins) a registry re-extraction and returns the promise to await - or null
 * when no heal is available right now (cooldown, standing down), in which case the
 * caller should fail fast instead of waiting on something that will not happen.
 */
// A 403 carrying a token-shaped API complaint means the API rejected this page's client
// tokens - almost always because a deploy just shipped and the page booted the previous
// bundle (stale HTML hides on the CDN edge even after the origin rotates). Recovering
// means forgetting the saved hints and dropping every in-memory page and the browser, so
// the next entry is forced to fetch fresh HTML and bind the new build; the stale registry
// guard takes it from there with its own heal.
const deployState = { lastAt: 0, running: false, promise: null };
function scheduleDeployRecovery(reason) {
  if (deployState.running) return deployState.promise;
  const now = Date.now();
  if (now - deployState.lastAt < DEPLOY_RECOVERY_COOLDOWN_MS) return null;
  deployState.lastAt = now;
  deployState.running = true;
  deployState.promise = (async () => {
    log.warn('403 on a tokened call looks like a deploy - recovering', { reason: reason.slice(0, 160) });
    routeHint = null;
    try { unlinkSync(HINT_FILE); } catch { /* already gone */ }
    await rebuild();
    log.info('deploy recovery ready - next entries fetch the fresh bundle');
  })()
    .catch((e) => log.error('deploy recovery failed', { error: String((e && e.message) || e).slice(0, 200) }))
    .finally(() => { deployState.running = false; });
  return deployState.promise;
}

function scheduleHeal(reason) {
  const now = Date.now();
  if (healState.running) return healState.promise;
  if (now - healState.lastAt < HEAL_COOLDOWN_MS) return null;
  healState.fails = healState.fails.filter((t) => now - t < 3600000);
  if (healState.fails.length >= HEAL_MAX_FAILS_PER_HOUR) {
    log.error('registry heal standing down for this hour', { fails: healState.fails.length, reason: reason.slice(0, 100) });
    return null;
  }
  healState.lastAt = now;
  healState.running = true;
  healState.promise = heal(reason)
    .catch((e) => log.error('registry heal crashed', { error: String((e && e.message) || e).slice(0, 200) }))
    .finally(() => { healState.running = false; });
  return healState.promise;
}

/**
 * Re-extracts the mapper registry from the bundle the pages are actually running, proves
 * the candidate against live requests for all three roles, and only then swaps it in.
 *
 * The chunk URL comes from the live binding (the site re-obfuscates the same file in
 * place, and sometimes renames it - the page knows which one it booted). The candidate is
 * injected into the working page directly, so validation exercises exactly the code path
 * a real request would.
 */
async function heal(reason) {
  const started = Date.now();
  let entry = idleEntry();
  if (!entry) {
    // Worth one jar: without a booted page there is neither a chunk URL nor a way to
    // validate the candidate.
    if (await buildEntry()) entry = entries[entries.length - 1];
  }
  if (!entry) throw new Error('no oracle entry to heal with');
  entry.busy = true;
  try {
    const routes = await evaluateWithin(entry, () => {
      const out = {};
      for (const r of ['list', 'chapters', 'pages']) {
        if (window.__oracleRoutes && window.__oracleRoutes[r]) out[r] = window.__oracleRoutes[r].chunk;
      }
      return out;
    }, undefined, EVAL_TIMEOUT_MS, 'heal routes');
    const chunkUrl = routes.list || routes.chapters || routes.pages;
    if (!chunkUrl) throw new Error('no bound chunk url to re-extract from');

    const chunkSrc = await evaluateWithin(
      entry,
      (u) => fetch(u).then((r) => { if (!r.ok) throw new Error('chunk fetch ' + r.status); return r.text(); }),
      chunkUrl,
      EVAL_TIMEOUT_MS,
      'heal chunk fetch',
    );
    const candidate = extractRegistry(chunkSrc);

    // Prove the candidate on this very page: inject it, then run one real request per
    // role through the normal path. A probe that answers is a registry that works. For
    // the chapters probe, a title the response cache already knows has chapters beats
    // hunting the listing - the newest-upload listing is often nothing but chapterless
    // fresh additions, so the hunt walks a few hids and gives up only after those.
    await evaluateWithin(entry, (reg) => { window.__oracleRegistry = reg; }, candidate, EVAL_TIMEOUT_MS, 'heal registry inject');
    const call = (spec) => evaluateWithin(
      entry,
      (pair) => (0, eval)('(' + pair[0] + ')')(pair[1]),
      [REQUEST_VIA_STORE_JS, spec],
      REQUEST_TIMEOUT_MS,
      'heal probe ' + spec.role,
    );
    const chaptersProbe = async (hid) => {
      await pokeUserInput(entry);
      let probe;
      try {
        probe = JSON.parse((await call({ role: 'chapters', id: hid, params: { limit: 2, order: { number: 'desc' }, page: 1 } })).json);
      } catch {
        return null; // a title without chapters answers 404 through the member
      }
      return probe.items && probe.items[0] && probe.items[0].number !== undefined ? probe : null;
    };
    let chapters = null;
    for (const key of cache.keys()) {
      const m = /^\/manga\/([^/]+)\/chapters\?/.exec(key);
      if (!m) continue;
      chapters = await chaptersProbe(m[1]).catch(() => null);
      if (chapters) break;
    }
    if (!chapters) {
      // Ordered by chapter_updated_at: only titles that actually have chapters surface.
      await pokeUserInput(entry);
      const listing = JSON.parse((await call({ role: 'list', params: { limit: 10, page: 1, order: { chapter_updated_at: 'desc' } } })).json);
      const hids = (listing.items || []).map((x) => x.hid).filter(Boolean).slice(0, 8);
      if (!hids.length) throw new Error('heal list probe produced no hids');
      for (const hid of hids) {
        chapters = await chaptersProbe(hid);
        if (chapters) break;
      }
    }
    if (!chapters) throw new Error('heal chapters probe found no chaptered title');
    await pokeUserInput(entry);
    const detail = JSON.parse((await call({ role: 'pages', id: String(chapters.items[0].id) })).json);
    if (!detail.pages || !Array.isArray(detail.pages.items) || !detail.pages.items.length || !detail.pages.items[0].url) {
      throw new Error('heal pages probe produced no page urls');
    }

    writeFileSync(REGISTRY_PATH + '.tmp', JSON.stringify(candidate));
    renameSync(REGISTRY_PATH + '.tmp', REGISTRY_PATH);
    loadRegistry(true);
    healState.lastSuccessAt = Date.now();
    stats.heals++;
    stats.lastHeal = { at: Date.now(), ms: Date.now() - started, roles: candidate.roles };
    log.info('registry healed from the live bundle', {
      ms: Date.now() - started, roles: JSON.stringify(candidate.roles), reason: reason.slice(0, 80),
    });
    // Every live entry still carries the stale registry under its skin.
    await rebuild();
  } finally {
    // A heal that failed anywhere leaves the entry carrying an injected candidate that
    // was never fully proven - that entry goes, whichever way the heal ended.
    if (entries.includes(entry)) discardEntry(entry);
  }
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
/**
 * Thrown when the caller hung up before the answer was ready.
 *
 * A jar and a page load cost real time that nobody will receive, so the work is abandoned
 * rather than finished: a request abandoned 16s after its client gave up still completed
 * here, spending a scarce jar on an answer that was thrown away.
 */
function abandoned() {
  const e = new Error('the caller went away before the answer was ready');
  e.abandoned = true;
  return e;
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
async function retryLoop(what, run, signal) {
  let lastError;
  // Abandonment can surface from three places - before a page is claimed, while waiting for
  // one, and inside the call - so it is counted here rather than at each of them.
  try {
    for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
      if (signal?.aborted) throw abandoned();
      const entry = await acquireEntry(signal);
      const outcome = await run(entry).then(
        (value) => ({ value }),
        (error) => ({ error }),
      );
      if (!outcome.error) {
        releaseEntry(entry);
        return outcome.value;
      }
      // The jar is the likely reason, so this entry and its jar both go, and the retry
      // builds a fresh one. A reload could not fix this: a jar that has stopped answering
      // stays stopped.
      discardEntry(entry);
      lastError = outcome.error;

      if (outcome.error.abandoned) throw outcome.error;
      const message = String((outcome.error && outcome.error.message) || outcome.error);
      // A stale registry is fixed by the heal it just triggered, not by a fresh jar: wait
      // for that heal, then spend the next attempt on the healed registry - the same
      // budget a 502 gets. If the heal does not land in time, the original error is as
      // permanent as ever.
      if (outcome.error.healWait) {
        const healedBefore = healState.lastSuccessAt;
        log.warn(`${what} hit a stale registry - waiting out the heal`, { attempt: attempt + 1, error: message });
        await Promise.race([
          outcome.error.healWait,
          new Promise((r) => setTimeout(r, HEAL_WAIT_TIMEOUT_MS)),
        ]);
        if (healState.lastSuccessAt === healedBefore) {
          stats.permanent++;
          log.error(`${what} failed - the registry heal did not land in time`, { attempt: attempt + 1, error: message });
          throw outcome.error;
        }
        continue;
      }
      // A 403 that fits the deploy signature schedules a recovery: hints flushed, browser
      // dropped, next entry fetches fresh HTML. Wait out the recovery with the same
      // budget a heal gets, then spend the next attempt on a freshly booted build.
      if (outcome.error.deployWait) {
        log.warn(`${what} hit a deploy signature 403 - waiting out the recovery`, { attempt: attempt + 1, error: message });
        await Promise.race([
          outcome.error.deployWait,
          new Promise((r) => setTimeout(r, DEPLOY_RECOVERY_WAIT_MS)),
        ]);
        // Recovery defers to the cooldown when one ran recently; then the retry proceeds
        // anyway - the attempts cap bounds the damage.
        continue;
      }
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
  } catch (e) {
    if (e && e.abandoned) stats.abandoned++;
    throw e;
  }
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
 * Runs inside the page. Calls the route-store member for `spec.role` and applies the
 * mappers registry backwards over its mapped output, so the oracle hands the caller the
 * same plain shapes the old /api/v1 pass-through served.
 *
 * Nothing here names a minified symbol: the members were picked by the request shape they
 * produce (window.__oracleFind) and cached on the page by PAGE_HELPERS, so a redeploy
 * is absorbed by re-finding rather than by a name.
 */
const REQUEST_VIA_STORE_JS = `
async function (spec) {
  var roles = window.__oracleRoutes;
  if (!roles || !roles[spec.role]) {
    if (!(await window.__oracleFind(window.__oracleHintRoutes))) {
      return { error: 'the bundle exposes no store member for ' + spec.role };
    }
    roles = window.__oracleRoutes;
  }
  try {
    var fn = roles[spec.role].fn;
    var raw = null;
    if (spec.role === 'list') raw = await fn(spec.params || {});
    else if (spec.role === 'chapters') raw = await fn(spec.id, spec.params || {});
    else raw = await fn(spec.id);
    var out = window.__oracleFlatten(spec.role, raw);
    if (typeof out !== 'string') return { error: out.error || 'flatten failed' };
    return { json: out };
  } catch (e) {
    var er = e && e.response;
    return { error: String((e && e.message) || e).slice(0, 300), status: er && er.status, body: JSON.stringify(er && er.data).slice(0, 200), url: er && er.config && String(er.config.url).slice(0, 140) };
  }
}
`;

/**
 * Splits an /api/v1 path into { role, id }:
 *   /manga                  -> { role: 'list' }      (no trailing slash - a trailing
 *                                                     slash is a different endpoint)
 *   /manga/<hid>/chapters   -> { role: 'chapters', id }
 *   /chapters/<chapterId>   -> { role: 'pages', id }
 * Anything else used to be heavier browsing endpoints the extension does not consume;
 * answering those with 404 here is cheaper than sending a member probing for them.
 */
function routeOf(apiPath) {
  const seg = apiPath.split('?')[0].split('/').filter(Boolean);
  if (seg.length === 1 && seg[0] === 'manga') return { role: 'list' };
  if (seg.length === 3 && seg[0] === 'manga' && seg[2] === 'chapters') return { role: 'chapters', id: seg[1] };
  if (seg.length === 2 && seg[0] === 'chapters') return { role: 'pages', id: seg[1] };
  return null;
}

/**
 * Plain JSON for the three API paths the extension consumes, answered by calling the
 * site's own store members and flattening their mapped output.
 *
 * Callers spell the path the way they spell a full URL (`/api/v1/manga`); the prefix is
 * only decoration the old proxy contract used, and the store members live above it.
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

export async function apiRequest(path, params = {}, { signal } = {}) {
  const apiPath = path.replace(/^\/api\/v1(?=\/|$)/, '') || '/';
  const route = routeOf(apiPath);
  if (!route) {
    // 404 rather than an origin probe: the extension never asks for anything else, and a
    // member probing for an unknown path could end up writing somewhere unintended.
    throw new Error(`unsupported api path (404): ${path}`);
  }
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
    if (signal?.aborted) throw abandoned();
    jarCalls++;
    await pokeUserInput(entry);
    const out = await evaluateWithin(
      entry,
      (pair) => (0, eval)('(' + pair[0] + ')')(pair[1]),
      [REQUEST_VIA_STORE_JS, { role: route.role, id: route.id, params }],
      REQUEST_TIMEOUT_MS,
      'api request',
    );
    if (out && out.error) {
      // A stale registry cannot be fixed by a fresh jar, but it can be fixed here: the
      // heal re-extracts the registry from the live bundle and swaps it in. When a heal
      // is available, its promise rides on the error so the retry loop can wait for it
      // and retry; when none is (cooldown, standing down) the error stays permanent -
      // failing fast beats burning jars on a request that cannot succeed yet.
      if (/registry does not match the served build|registry has no mapper/.test(out.error)) {
        const healPromise = scheduleHeal(out.error);
        const error = new Error(out.error);
        if (healPromise) error.healWait = healPromise;
        throw error;
      }
      const detail = [out.error, out.status && 'status=' + out.status, out.body && 'body=' + out.body, out.url && 'url=' + out.url].filter(Boolean).join(' | ');
      if (out.status === 403 && /missing_token|invalid_token|token/.test(String(out.body || ''))) {
        // The API still talks JSON, it just refuses this client: the bundle in the page is
        // stale. Forget the hints, flush every page, and let the next attempt boot the
        // new build. Rides the retry the same way a stale-registry heal does.
        const deployPromise = scheduleDeployRecovery(detail);
        const error = new Error(detail);
        if (deployPromise) error.deployWait = deployPromise;
        throw error;
      }
      throw new Error(detail);
    }
    if (!out || typeof out.json !== 'string') throw new Error(`no body for ${path}`);
    return out.json;
  };
  const json = await retryLoop('request', run, signal);

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
    served: entries.reduce((n, e) => n + e.served, 0),
    building: building.length,
    pages: entries.length,
    inUse: entries.filter((e) => e.busy).length,
    waiting: waiters.length,
    cache: { size: cache.size, hits: cacheHits, misses: cacheMisses, ttlMs: CACHE_TTL_MS },
    heals: stats.heals,
    healFails: stats.healFails,
    lastHeal: stats.lastHeal,
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
