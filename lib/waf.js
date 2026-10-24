// Cloudflare clearance, solved by FlareSolverr.
//
// Two things learned the hard way, both load-bearing:
//   - FlareSolverr hands back more than cf_clearance (the site also sets `session`).
//     Sending cf_clearance alone leaves every request on Cloudflare's 403 page, so the
//     whole jar has to travel together.
//   - cf_clearance is bound to the user agent it was solved with, so the UA is returned
//     alongside it and every caller echoes it.
//
// The site's own captcha (@waf/generate -> @waf/verify, yielding waf_pass) used to live
// here. It is gone: @waf/generate answers 500 "captcha generation failed" and no challenge
// is ever issued, and the API never demanded the cookie anyway, so the solver and its image
// dependencies went with it.
import fs from 'node:fs';
import { log, isDebug } from './log.js';

const FS_BASE = process.env.FLARESOLVERR_URL || 'http://flaresolverr:8191/v1';
const COOKIE_TTL_MS = 25 * 60 * 1000; // cf_clearance ~30min, refresh a bit early
// Solved jars on disk, so a restart does not start cold.
//
// The buffer holds ~20 jars and FlareSolverr manages about 0.2/s, so refilling from empty
// takes well over a minute. Anything arriving in that window queues behind four page slots
// and an 11s solve and blows the client's 35s timeout. A cf_clearance is good for ~25
// minutes, so a restart inside that window can simply pick up where it left off - which
// covers a redeploy or a crash, the two times a restart is actually unexpected.
//
// Survives `docker restart` on its own. Mount a volume over this path to also survive a
// rebuild, which replaces the container and its filesystem.
const JAR_STORE = process.env.WAF_JAR_STORE || '/app/.jars';
// Restoring a jar with a minute left would hand out a clearance that fails, and a failed
// page costs a whole load to discover, so nothing this close to expiry is worth keeping.
const MIN_LIFE_MS = Number(process.env.WAF_JAR_MIN_LIFE_MS || 5 * 60 * 1000);

let current = null;

async function fsRequest(payload) {
  const res = await fetch(FS_BASE, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error(`FlareSolverr HTTP ${res.status}`);
  const j = await res.json();
  if (j.status !== 'ok' || !j.solution) {
    throw new Error(`FlareSolverr: ${j.message || JSON.stringify(j).slice(0, 200)}`);
  }
  return j.solution;
}

/**
 * Jars solved ahead of time.
 *
 * The site allows only a couple of API calls per cookie jar and answers 502 after that -
 * Cloudflare reporting that comix.to's own origin failed (`origin_bad_gateway`,
 * `retry-after: 60`). Measured: a fresh jar serves exactly one call of ours and answers 502
 * to every one after it, whatever the URL, and the budget never comes back - the same jar
 * was still dead after a minute. Loading a page is free; only the API call is charged, and
 * responses Cloudflare can serve from its edge (`x-cache: HIT`) do not reach the origin at
 * all, which is why a jar sometimes seems to last two.
 *
 * So a jar is now consumed per request rather than shared, and FlareSolverr takes ~11s to
 * produce one. That makes the solve the bottleneck for everything, so jars are solved
 * continuously in the background and a request takes one that is already ready.
 *
 * The buffer has to be deep because the load is bursty, not steady. Suwayomi fires a
 * library refresh as a dozen simultaneous chapter-list calls; at FlareSolverr's ceiling of
 * ~0.3 solves/s that drains a shallow buffer in seconds and the rest of the burst waits on
 * solves, which is what pushed requests past the client's 30s timeout. Measured on a 6-deep
 * buffer: 35% of requests over 5s and a tail piled against 30s, while average demand was
 * only ~0.03 jars/s. Depth costs nothing but a solve - a jar is cookies - so it is set well
 * above the burst size rather than tuned to the average.
 */
const JAR_BUFFER = Math.max(1, Number(process.env.WAF_JAR_BUFFER || 20));
// How many solves may be in flight at once.
//
// This is FlareSolverr's capacity, not our appetite, and the two are easy to confuse: asking
// for a 20-deep buffer used to mean 20 simultaneous solves, which queues inside FlareSolverr
// at ~11s each. The 17th entry then waited nearly three minutes against our own 60s
// maxTimeout and was failed outright. Measured directly: 1/2/3 concurrent all succeed in
// ~11-12s, the fourth starts failing, and six take 23s for less throughput than three.
// Buffer depth is reached over time by three-at-a-time; it is not a reason to solve faster.
const SOLVE_CONCURRENCY = Math.max(1, Number(process.env.WAF_SOLVE_CONCURRENCY || 3));
// Backoff after a failed solve, doubling up to a ceiling. A solve that cannot reach
// FlareSolverr fails in milliseconds, so retrying straight away is a spin rather than a
// retry - and the log fills faster than anyone can read it.
const BACKOFF_BASE_MS = Number(process.env.WAF_BACKOFF_BASE_MS || 1000);
const BACKOFF_MAX_MS = Number(process.env.WAF_BACKOFF_MAX_MS || 30000);
const ready = [];
let solving = 0;
let solves = 0;
let solveFailures = 0;
let consecutiveFailures = 0;
let notBefore = 0;
let handedOut = 0;
let restored = 0;
let storeUsable = true;

const jarFile = (cf) => `${JAR_STORE}/jar-${String(cf.solvedAt).padStart(14, '0')}.json`;

/** Fills the buffer from disk. Called once at startup; never fatal if the store is unusable. */
function restoreJars() {
  let files;
  try {
    files = fs.readdirSync(JAR_STORE).filter((f) => f.startsWith('jar-') && f.endsWith('.json'));
  } catch (e) {
    // A store that does not exist yet is the normal first run, not a broken one. Anything
    // else (unwritable mount, bad path) is worth reporting and worth giving up on.
    if (e && e.code === 'ENOENT') {
      try { fs.mkdirSync(JAR_STORE, { recursive: true }); } catch { storeUsable = false; }
      return 0;
    }
    log.warn('cannot read the jar store; restarts will start cold', {
      error: String((e && e.message) || e),
      store: JAR_STORE,
    });
    storeUsable = false;
    return 0;
  }
  let kept = 0;
  for (const file of files.sort()) {
    const full = `${JAR_STORE}/${file}`;
    try {
      const raw = JSON.parse(fs.readFileSync(full, 'utf8'));
      if (!raw?.expiryMs || raw.expiryMs - Date.now() < MIN_LIFE_MS) {
        fs.unlinkSync(full);
        continue;
      }
      ready.push(makeJar(raw));
      kept++;
    } catch {
      // A half-written or corrupt file is worse than no file.
      try { fs.unlinkSync(full); } catch { /* leave it; it is ignored either way */ }
    }
  }
  restored = kept;
  if (kept) log.info('restored jars from disk', { kept, store: JAR_STORE });
  return kept;
}

function persistJar(cf) {
  if (!storeUsable) return;
  try {
    fs.mkdirSync(JAR_STORE, { recursive: true });
    fs.writeFileSync(jarFile(cf), JSON.stringify({
      solvedAt: cf.solvedAt,
      expiryMs: cf.expiryMs,
      userAgent: cf.userAgent,
      cookies: cf.cookies,
    }));
  } catch (e) {
    // Worth saying once: without this, every restart is slow again and the logs will not
    // otherwise say why.
    log.warn('cannot persist jars; restarts will start cold', { error: String((e && e.message) || e), store: JAR_STORE });
    storeUsable = false;
  }
}

function forgetJar(cf) {
  if (!cf?.solvedAt) return;
  try { fs.unlinkSync(jarFile(cf)); } catch { /* already gone */ }
}

/** Tops the buffer up to [target] jars, counting ones already being solved. */
export function prewarmCookies(target = JAR_BUFFER) {
  // Both limits matter: `target` is how much stock to keep, SOLVE_CONCURRENCY is how hard
  // FlareSolverr can be driven while keeping to it.
  if (Date.now() < notBefore) return;
  while (solving + ready.length < target && solving < SOLVE_CONCURRENCY) {
    solving++;
    const started = Date.now();
    solveJar().then(
      (cf) => {
        consecutiveFailures = 0;
        notBefore = 0;
        ready.push(cf);
        solves++;
        persistJar(cf);
        log.debug('jar solved', { ms: Date.now() - started, ready: ready.length, total: solves });
      },
      (e) => {
        // Without a pause this is a spin: a solve that fails returns in milliseconds, the
        // refill asks again straight away, and an unreachable FlareSolverr turns into
        // thousands of failures a second. Measured: 2056 of them before anything else was
        // even logged.
        solveFailures++;
        consecutiveFailures++;
        const backoff = Math.min(BACKOFF_MAX_MS, BACKOFF_BASE_MS * 2 ** Math.min(consecutiveFailures - 1, 5));
        notBefore = Date.now() + backoff;
        log.warn('jar solve failed', {
          error: String((e && e.message) || e),
          failures: solveFailures,
          retryInMs: backoff,
        });
      },
    ).finally(() => {
      solving--;
      prewarmCookies(target);
    });
  }
}

/** Takes a ready jar if the buffer has one, so a request does not wait on a solve. */
function takeSolvedJar() {
  // Skip anything that aged out while it sat in the buffer or on disk.
  while (ready.length && ready[0].expiryMs - Date.now() < MIN_LIFE_MS) {
    forgetJar(ready.shift());
  }
  if (!ready.length) return null;
  const jar = ready.shift();
  forgetJar(jar); // spent on handout: it is about to be consumed by exactly one request
  if (isDebug()) log.debug('taking a pre-solved jar', { remaining: ready.length });
  return jar;
}

/**
 * Keeps the buffer topped up for as long as the process runs.
 *
 * Once a jar is worth a single request, the buffer is not an optimisation but the supply:
 * an empty buffer means every request waits on an ~11s solve. Solving only on demand was
 * fine when one jar served many calls and is unusable now.
 */
let filling = false;
export function keepBufferFull() {
  if (filling) return;
  filling = true;
  restoreJars();
  (async () => {
    while (filling) {
      prewarmCookies();
      await new Promise((r) => setTimeout(r, 2000));
    }
  })().catch((e) => log.error('jar filler stopped', { error: String((e && e.message) || e) }));
}

/**
 * A jar for exactly one request, never reused.
 *
 * Kept separate from getCfClearance because that one hands back the same jar until it
 * expires, which is the behaviour that produced the 502s: sharing a jar across a pool of
 * pages looks efficient and is what spends the whole budget on the first caller.
 */
export async function acquireJar() {
  const jar = takeSolvedJar() ?? await solveJar();
  handedOut++;
  // Recorded so /cookies reports what is actually in use rather than a jar from boot.
  current = jar;
  if (isDebug()) log.debug('acquired a jar', { handedOut, remaining: ready.length });
  return jar;
}

/** Assembles a jar from what FlareSolverr returned, or from what was read back off disk. */
function makeJar({ cookies, userAgent, expiryMs, solvedAt }) {
  const cfCookie = (cookies || []).find((c) => c.name === 'cf_clearance');
  if (!cfCookie) throw new Error('no cf_clearance cookie');
  return {
    cookies,
    jar: cookies.map((c) => `${c.name}=${c.value}`).join('; '),
    value: cfCookie.value,
    userAgent,
    expiryMs,
    solvedAt,
  };
}

async function solveJar() {
  // Deliberately not pinned to a FlareSolverr session: a pinned session replays the same
  // `session` cookie every time, so forcing a refresh returned byte-identical cookies and
  // the site's per-jar API budget never reset. Each solve gets its own temporary session.
  //
  // The jar's cookies come from the WAF challenge page, not the homepage: the chapters and
  // pages endpoints demand the captcha pass (403 captcha_required), and the pass rides on
  // the cookies FlareSolverr answers with when it clears the Turnstile at /@waf/challenge.
  // A homepage solve would carry no pass at all.
  const sol = await fsRequest({
    cmd: 'request.get',
    url: 'https://comix.to/@waf/challenge',
    maxTimeout: 90000,
  });
  let cookies = sol.cookies || [];
  const cfCookie = cookies.find((c) => c.name === 'cf_clearance');
  if (!cfCookie) throw new Error('FlareSolverr returned no cf_clearance cookie');
  // The oracle pages need `session` beside cf_clearance or the bundle never boots; the
  // challenge page does not always set one, so top it up from a plain homepage solve.
  if (!cookies.some((c) => c.name === 'session')) {
    const home = await fsRequest({ cmd: 'request.get', url: 'https://comix.to/', maxTimeout: 60000 });
    const session = (home.cookies || []).find((c) => c.name === 'session');
    if (session) cookies = [...cookies, session];
  }
  const solvedAt = Date.now();
  return {
    cookies,
    jar: cookies.map((c) => `${c.name}=${c.value}`).join('; '),
    value: cfCookie.value,
    userAgent: sol.userAgent,
    expiryMs: solvedAt + Math.min((cfCookie.expiry ?? 1800) * 1000, COOKIE_TTL_MS),
    solvedAt,
  };
}

/**
 * The current jar, for callers that need cookies without spending one.
 *
 * Returns whatever acquireJar last handed out, which is spent by definition. Anything that
 * makes a request should be using acquireJar so it gets a jar with budget left in it.
 */
export async function getCfClearance() {
  if (!current) current = await acquireJar();
  return current;
}

/** How the jar buffer is doing, for /health. */
export function jarBufferStats() {
  return {
    ready: ready.length,
    solving,
    buffer: JAR_BUFFER,
    maxSolving: SOLVE_CONCURRENCY,
    solves,
    failed: solveFailures,
    backoffMs: Math.max(0, notBefore - Date.now()),
    handedOut,
    restored,
    store: storeUsable,
  };
}
