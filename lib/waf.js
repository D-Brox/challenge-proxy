// WAF captcha + Cloudflare clearance solving.
// cf_clearance comes from FlareSolverr; the site's own captcha (@waf/generate ->
// @waf/verify) yields the waf_pass cookie.
//
// Two things learned the hard way, both load-bearing:
//   - FlareSolverr hands back more than cf_clearance (the site also sets `session`).
//     Sending cf_clearance alone leaves every request on Cloudflare's 403 page, so the
//     whole jar has to travel together.
//   - cf_clearance is bound to the user agent it was solved with, so the UA is returned
//     alongside it and every caller echoes it.
import { PNG } from 'pngjs';
import { estimateRotationAngle } from './rotation.js';
import { decodeImage, solve as solveShapes, confident as shapesConfident } from './shapes.js';
import { log, isDebug } from './log.js';

const FS_BASE = process.env.FLARESOLVERR_URL || 'http://flaresolverr:8191/v1';
const COOKIE_TTL_MS = 25 * 60 * 1000; // cf_clearance ~30min, refresh a bit early
const CHALLENGES_PER_ROUND = Number(process.env.WAF_CHALLENGES_PER_ROUND || 5);
const MAX_ROUNDS = Number(process.env.WAF_MAX_ROUNDS || 3);

let state = {
  cf: null, // { jar, value, userAgent, expiryMs }
  waf: null, // { value, expiryMs }
};

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
 * The site allows only a handful of API calls per cookie jar and answers 502 afterwards, so
 * a fresh jar is needed constantly, and FlareSolverr takes ~11s to produce one - an order of
 * magnitude longer than the session swap it feeds. Solving one jar ahead is not enough: a
 * two-call jar is spent in about a second, far sooner than the next solve lands. So a small
 * buffer is kept topped up instead, and a rotation takes a ready jar rather than waiting.
 *
 * FlareSolverr parallelises well - three concurrent solves finish in the same ~11.7s as one -
 * so the buffer refills at roughly JAR_BUFFER jars per solve interval.
 */
const JAR_BUFFER = Math.max(1, Number(process.env.WAF_JAR_BUFFER || 3));
const ready = [];
let solving = 0;
let solves = 0;

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

/** Takes a ready jar if the buffer has one, so a rotation does not wait on a solve. */
function takeSolvedJar() {
  if (!ready.length) return null;
  if (isDebug()) log.debug('taking a pre-solved jar', { remaining: ready.length });
  return ready.shift();
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
  const expiryMs = Date.now() + Math.min((cfCookie.expiry ?? 1800) * 1000, COOKIE_TTL_MS);
  const cf = {
    cookies,
    jar: cookies.map((c) => `${c.name}=${c.value}`).join('; '),
    value: cfCookie.value,
    userAgent: sol.userAgent,
    expiryMs,
  };
  // waf_pass is bound to the cf session's UA+IP; invalidate it so it is re-solved
  // with the new clearance.
  state.waf = null;
  return cf;
}

export async function getCfClearance(force = false) {
  if (!force && state.cf && Date.now() < state.cf.expiryMs) {
    return state.cf;
  }
  if (!force) log.debug('solving cookies');
  state.cf = takeSolvedJar() ?? await solveJar();
  return state.cf;
}

function buildHeaders(cf) {
  return {
    'User-Agent': cf.userAgent,
    Referer: 'https://comix.to/',
    Origin: 'https://comix.to',
    Accept: 'application/json',
    Cookie: cf.jar,
  };
}

async function wafGenerate(headers) {
  const res = await fetch('https://comix.to/@waf/generate', { headers });
  const text = await res.text();
  // The layer likes to answer 200 with a challenge page instead of a challenge,
  // so the body has to be checked rather than the status alone.
  let challenge = null;
  try {
    challenge = JSON.parse(text);
  } catch {
    throw new Error(`@waf/generate returned a page, not a challenge (HTTP ${res.status})`);
  }
  if (!challenge || !challenge.captcha_id) {
    throw new Error(`@waf/generate returned no captcha_id (HTTP ${res.status}): ${text.slice(0, 120)}`);
  }
  return challenge;
}

async function wafVerify(captchaId, answer, headers) {
  const body = { captcha_id: captchaId };
  if (answer.dots !== undefined) body.dots = answer.dots;
  if (answer.angle !== undefined) body.angle = answer.angle;
  const res = await fetch('https://comix.to/@waf/verify', {
    method: 'POST',
    headers: { ...headers, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const setCookie = res.headers.get('set-cookie') || '';
  let payload = {};
  try {
    payload = await res.json();
  } catch {
    payload = {};
  }
  const cookie = setCookie.split(';').find((c) => c.trim().startsWith('waf_pass='));
  return { success: !!payload.success, cookie: cookie ? cookie.trim() : null };
}

/** Answers one challenge, or null when the picture is too ambiguous to commit to. */
function planChallenge(challenge) {
  if (challenge.count > 0) {
    const plan = solveShapes(
      decodeImage(challenge.image_base64),
      decodeImage(challenge.thumb_base64),
      challenge.count,
    );
    return plan ? { dots: plan.dots, margin: plan.margin } : null;
  }
  if (challenge.thumb_size > 0) {
    const image = PNG.sync.read(Buffer.from(String(challenge.image_base64).split(',').pop(), 'base64'));
    const thumb = PNG.sync.read(Buffer.from(String(challenge.thumb_base64).split(',').pop(), 'base64'));
    const angle = estimateRotationAngle(image.data, image.width, thumb.data, thumb.width);
    return { angle: angle % 360, margin: Infinity };
  }
  return null;
}

async function trySolve() {
  const cf = await getCfClearance();
  const headers = buildHeaders(cf);

  let best = null;
  let bestAnswer = null;
  for (let attempt = 0; attempt < CHALLENGES_PER_ROUND; attempt++) {
    const challenge = await wafGenerate(headers);
    const answer = planChallenge(challenge);
    if (answer && (!bestAnswer || answer.margin > bestAnswer.margin)) {
      best = challenge;
      bestAnswer = answer;
    }
    // captcha_id is single-use; a fresh challenge each round
    if (bestAnswer && (bestAnswer.margin === Infinity || shapesConfident(bestAnswer))) break;
  }
  if (!best || !bestAnswer) return null;

  const verify = await wafVerify(best.captcha_id, bestAnswer, headers);
  if (!verify.success || !verify.cookie) return null;
  const match = verify.cookie.match(/^waf_pass=([^;]+)/);
  const value = match ? match[1] : null;
  if (!value) return null;
  // Max-Age=1800 from the server
  return { value, expiryMs: Date.now() + 25 * 60 * 1000 };
}

export async function getWafPass(force = false) {
  if (!force && state.waf && Date.now() < state.waf.expiryMs) {
    return state.waf;
  }
  for (let round = 0; round < MAX_ROUNDS; round++) {
    const solved = await trySolve();
    if (solved) {
      state.waf = solved;
      log.info('waf_pass solved', { round: round + 1 });
      return solved;
    }
  }
  log.error('could not solve the WAF captcha', { rounds: MAX_ROUNDS });
  throw new Error(`Failed to solve the WAF captcha after ${MAX_ROUNDS} rounds`);
}

/**
 * Everything a caller needs to make one signed request: the whole cookie jar, the
 * cf_clearance on its own for callers that assemble their own header, and the UA the
 * clearance is bound to.
 *
 * A missing waf_pass is reported rather than thrown. The site is currently answering
 * @waf/generate with 500, and the API only demands the `_` token, so failing to earn a
 * captcha cookie must not stop requests being signed.
 */
export async function ensureCookies(force = false) {
  const cf = force ? await getCfClearance(true) : await getCfClearance();
  let wafPass = '';
  try {
    const waf = force ? await getWafPass(true) : await getWafPass();
    wafPass = waf.value;
  } catch (e) {
    // Not fatal: the API only demands the `_` token, and the proxy's own requests carry
    // their cookies, so a missing captcha cookie is worth reporting but not failing on.
    log.warn('waf_pass unavailable', { error: String((e && e.message) || e) });
  }
  const jar = wafPass ? `${cf.jar}; waf_pass=${wafPass}` : cf.jar;
  return {
    waf_pass: wafPass,
    cf_clearance: cf.value,
    user_agent: cf.userAgent,
    cookie: jar,
  };
}

/** How the jar buffer is doing, for /health. */
export function jarBufferStats() {
  return { ready: ready.length, solving, buffer: JAR_BUFFER, solves };
}
