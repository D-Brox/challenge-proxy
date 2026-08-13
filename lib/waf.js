// WAF (rotate-to-align captcha) + Cloudflare clearance solving.
// cf_clearance comes from FlareSolverr; the site's own rotate captcha
// (@waf/generate -> @waf/verify) yields the waf_pass cookie.
import { PNG } from 'pngjs';
import { estimateRotationAngle } from './rotation.js';

const FS_BASE = process.env.FLARESOLVERR_URL || 'http://flaresolverr:8191/v1';
const COOKIE_TTL_MS = 25 * 60 * 1000; // cf_clearance ~30min, refresh a bit early

let state = {
  cf: null, // { value, userAgent, expiryMs }
  waf: null, // { value, expiryMs }
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

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

export async function getCfClearance(force = false) {
  if (!force && state.cf && Date.now() < state.cf.expiryMs) {
    return state.cf;
  }
  const sol = await fsRequest({
    cmd: 'request.get',
    url: 'https://comix.to/',
    maxTimeout: 60000,
    session: 'comix',
  });
  const cfCookie = (sol.cookies || []).find((c) => c.name === 'cf_clearance');
  if (!cfCookie) throw new Error('FlareSolverr returned no cf_clearance cookie');
  const expiryMs = Date.now() + Math.min((cfCookie.expiry ?? 1800) * 1000, COOKIE_TTL_MS);
  state.cf = { value: cfCookie.value, userAgent: sol.userAgent, expiryMs };
  // waf_pass is bound to the cf session's UA+IP; invalidate it so it is re-solved
  // with the new clearance.
  state.waf = null;
  return state.cf;
}

async function wafGenerate(headers) {
  const res = await fetch('https://comix.to/@waf/generate', { headers });
  if (!res.ok) throw new Error(`@waf/generate HTTP ${res.status}`);
  return res.json();
}

async function wafVerify(captchaId, angle, headers) {
  const res = await fetch('https://comix.to/@waf/verify', {
    method: 'POST',
    headers: { ...headers, 'Content-Type': 'application/json' },
    body: JSON.stringify({ captcha_id: captchaId, angle }),
  });
  const setCookie = res.headers.get('set-cookie') || '';
  const body = await res.json();
  const cookie = setCookie.split(';').find((c) => c.trim().startsWith('waf_pass='));
  return { success: !!body.success, cookie: cookie ? cookie.trim() : null };
}

function buildHeaders(cf) {
  return {
    'User-Agent': cf.userAgent,
    Referer: 'https://comix.to/',
    Origin: 'https://comix.to',
    Accept: 'application/json',
    Cookie: `cf_clearance=${cf.value}`,
  };
}

export async function getWafPass(force = false) {
  if (!force && state.waf && Date.now() < state.waf.expiryMs) {
    return state.waf;
  }
  const cf = await getCfClearance();
  const headers = buildHeaders(cf);

  for (let attempt = 0; attempt < 3; attempt++) {
    const challenge = await wafGenerate(headers);
    const origPng = PNG.sync.read(Buffer.from(challenge.image_base64.split(',')[1], 'base64'));
    const thumbPng = PNG.sync.read(Buffer.from(challenge.thumb_base64.split(',')[1], 'base64'));
    const angle = estimateRotationAngle(
      origPng.data, origPng.width,
      thumbPng.data, thumbPng.width,
    );
    const verify = await wafVerify(challenge.captcha_id, angle % 360, headers);
    if (verify.success && verify.cookie) {
      const match = verify.cookie.match(/^waf_pass=([^;]+)/);
      const value = match ? match[1] : null;
      if (!value) continue;
      // Max-Age=1800 from the server
      state.waf = { value, expiryMs: Date.now() + 25 * 60 * 1000 };
      return state.waf;
    }
    // captcha_id is single-use; try again with a fresh challenge
  }
  throw new Error('Failed to solve WAF captcha after 3 attempts');
}

// Returns everything the extension needs to sign one request: the token is
// minted by the caller; here we refresh cookies as needed.
export async function ensureCookies(force = false) {
  const cf = force ? await getCfClearance(true) : await getCfClearance();
  const waf = force ? await getWafPass(true) : await getWafPass();
  return {
    waf_pass: waf.value,
    cf_clearance: cf.value,
    user_agent: cf.userAgent,
  };
}
