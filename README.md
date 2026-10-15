# Comix Proxy server

A server that signs and decodes comix.to API requests and keeps the WAF cookies
those requests need, so the extension never has to boot a WebView to do crypto.

The site re-obfuscates its bundle on every deploy. It used to ship a plain
S-box cipher whose material could be lifted out of the bundle and reimplemented,
but the current bundle puts the signing and decoding primitives behind a bytecode
VM. Reimplementing that would mean porting the VM, so instead this server keeps
the **real bundle running in a headless Chromium** and asks it for a token or a
decoded body. That also means a redeploy needs no change here: the browser loads
whatever is live and finds the primitives by behaviour, never by name.

The bundle also sits behind Cloudflare, and Cloudflare clearance comes from
FlareSolverr. The site's own `@waf/generate` endpoint is gone — the current site serves a
Cloudflare Turnstile widget instead — so there is no captcha to solve here. `waf_pass` is
still requested and stored when the site hands one out, but it is best-effort and never
blocks signing; `cf_clearance` is the cookie that actually matters.

## The recovered cipher

`lib/signer.js` is a pure-Node reimplementation of the signing algorithm, recovered by
tracing the bundle's bytecode VM. It implements, and `test-signer.mjs` asserts against a
captured trace of the site's own code:

- **canonicalisation** — `/api/v1` stripped, nested objects flattened to bracketed paths
  (`order: {number:'desc'}` → `order[number]=desc`), arrays as `key[i]`, sorted
- **word stream** — big-endian uint32, final partial word padded `0x80` then zeros
- **the mixer** — a 48-iteration feedback loop over one master stream:
  `key = f(S[i+1])`, `inp = g(S[i+14])`, `p = S[i] + key`, `acc = p + S[i+9]`, `q = acc + inp`,
  where `f(x) = rotr(x,7) ^ rotr(x,18) ^ (x>>>3)` and `g(x) = rotr(x,17) ^ rotr(x,19) ^ (x>>>10)`
- **the expansion chains** — four 192-long chains, each verified 192/192
- **output** — eight lanes as big-endian 4-byte words → base64url → first 16 characters

```
node test-signer.mjs        # 8 stages, all green
```

It is **not yet used by the server.** The one gap is that the chain constants
`C20..C23` are request-derived rather than material-derived, so `sign()` reproduces a
token for the chain constants it is given but cannot derive them from the material alone.
`/sign` therefore still goes through the oracle.

### The material

`material()` returns 1088 bytes (272 big-endian words). Only the **first 64 bytes —
words 0..15, 5.9% of it — participate in signing**: words 0..7 feed the expansion seeds,
and words 0..3 and 4..7 seed the chains. None of the seed or chain constants are material
words or derivable from them, so the bulk of the key lives in constants baked into the
bundle at build time, not in `material()`.

## Usage

```
git clone https://github.com/D-Brox/challenge-proxy.git
cd challenge-proxy
git checkout comix-proxy
```

With docker:
```
docker compose up -d
```

Or directly with Node 18+ (needs a Chromium and a FlareSolverr to point at):
```
npm install
FLARESOLVERR_URL=http://localhost:8191/v1 CHROMIUM_PATH=/usr/bin/chromium node server.mjs
```

The server listens on `http://localhost:9191` by default.

## Endpoints

- `GET /sign?path=${api_path}&qs=${canonical_query}[&force=1]` — returns
  `{"token", "waf_pass", "cf_clearance", "user_agent"}`. `qs` arrives already
  canonicalized by the client and is used verbatim. `force=1` re-solves the
  cookies instead of reusing them.
- `POST /decrypt` with `{"e": "<envelope>"}` — returns `{"json": "<decoded body>"}`.
- `GET /cookies?force=1` — returns the current `cf_clearance`, `waf_pass` and
  `user_agent`, for when a request is served a fresh captcha.
- `GET /health` — liveness plus oracle counters (`signs`, `decrypts`, `rebuilds`).

`/refresh-material` and `/load-material` are kept for the client, which still
calls them to recover from a redeploy. There is no longer any material on disk,
so both simply make sure the live bundle is loaded: `/refresh-material` rebuilds
the page, `/load-material` reports whether it is up.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | `9191` | listen port |
| `FLARESOLVERR_URL` | `http://flaresolverr:8191/v1` | FlareSolverr endpoint |
| `CHROMIUM_PATH` | — | Chromium to drive for the oracle |
| `COMIX_BASE` | `https://comix.to` | site origin |
| `ORACLE_READY_TIMEOUT_MS` | `30000` | how long to wait for the bundle to publish its primitives |
| `ORACLE_EVAL_TIMEOUT_MS` | `20000` | per-call evaluation budget |
| `WAF_CHALLENGES_PER_ROUND` | `5` | captchas sampled before committing to an answer |
| `WAF_MAX_ROUNDS` | `3` | rounds before giving up on `waf_pass` |

## The client side

The `comix-challenge.patch` file in this repository is the client-side half: the
changes to the Comix Tachiyomi/Suwayumi extension that make it talk to this
server (proxy preference, `/sign`-minted tokens, `/decrypt`-decoded envelopes,
mirrored `cf_clearance`/`waf_pass` cookies and UA). The same client changes live
on the `comix-proxy` branch of the extension repository.

## Disclaimer

This project interacts with the public comix.to web/API surface. The captcha
solving and cookie handling are for interoperability with an API the extension
client is already entitled to use. Use at your own discretion.
