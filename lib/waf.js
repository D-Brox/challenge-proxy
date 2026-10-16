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
import { log, isDebug } from './log.js';

const FS_BASE = process.env.FLARESOLVERR_URL || 'http://flaresolverr:8191/v1';
const COOKIE_TTL_MS = 25 * 60 * 1000; // cf_clearance ~30min, refresh a bit early

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
 */
const JAR_BUFFER = Math.max(1, Number(process.env.WAF_JAR_BUFFER || 6));
const ready = [];
let solving = 0;
let solves = 0;
let handedOut = 0;

/** Tops the buffer up to [target] jars, counting ones already being solved. */
export function prewarmCookies(target = JAR_BUFFER) {
  while (solving + ready.length < target) {
    solving++;
    const started = Date.now();
    solveJar().then(
      (cf) => {
        ready.push(cf);
        solves++;
        log.debug('jar solved', { ms: Date.now() - started, ready: ready.length, total: solves });
      },
      (e) => log.warn('jar solve failed', { error: String((e && e.message) || e) }),
    ).finally(() => {
      solving--;
      prewarmCookies(target);
    });
  }
}

/** Takes a ready jar if the buffer has one, so a request does not wait on a solve. */
function takeSolvedJar() {
  if (!ready.length) return null;
  if (isDebug()) log.debug('taking a pre-solved jar', { remaining: ready.length });
  return ready.shift();
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

async function solveJar() {
  // Deliberately not pinned to a FlareSolverr session: a pinned session replays the same
  // `session` cookie every time, so forcing a refresh returned byte-identical cookies and
  // the site's per-jar API budget never reset. Each solve gets its own temporary session.
  const sol = await fsRequest({
    cmd: 'request.get',
    url: 'https://comix.to/',
    maxTimeout: 60000,
  });
  const cookies = sol.cookies || [];
  const cfCookie = cookies.find((c) => c.name === 'cf_clearance');
  if (!cfCookie) throw new Error('FlareSolverr returned no cf_clearance cookie');
  return {
    cookies,
    jar: cookies.map((c) => `${c.name}=${c.value}`).join('; '),
    value: cfCookie.value,
    userAgent: sol.userAgent,
    expiryMs: Date.now() + Math.min((cfCookie.expiry ?? 1800) * 1000, COOKIE_TTL_MS),
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
  return { ready: ready.length, solving, buffer: JAR_BUFFER, solves, handedOut };
}
