# Comix Proxy server

A server that signs comix.to API requests and fetches protected bodies, so the
extension never has to boot a WebView to do crypto.

The site re-obfuscates its bundle on every deploy. It used to ship a plain
S-box cipher whose material could be lifted out of the bundle and reimplemented,
but the current bundle puts the signing and decoding primitives behind a bytecode
VM. Reimplementing that would mean porting the VM, so instead this server keeps
the **real bundle running in a headless Chromium** and asks it for a token or a
decoded body. That also means a redeploy needs no change here: the browser loads
whatever is live and finds the primitives by behaviour, never by name.

The bundle also sits behind Cloudflare, and Cloudflare clearance comes from
FlareSolverr. The site's own `@waf/generate` endpoint is gone — it answers `500
captcha generation failed` and never issues a challenge, so there is no captcha to solve
here and none of the image processing that went with it. `cf_clearance` is the cookie that
matters.

### One jar per request

A cookie jar is worth about **one** API call. After that the site answers `502` to
everything on it, whatever the URL, and the budget never comes back — the same jar was
still dead a minute later. The 502 is Cloudflare reporting that comix.to's own origin
failed (`origin_bad_gateway`, `retry-after: 60`), not a rate limit and not the site's
"no user input" flag, which is not set on those requests.

So a jar is **kept until it actually fails**, rather than spent on a guess. One page holds one
jar and serves many requests; the first failure discards both and the retry builds a fresh
pair. Measured on a warm pool: 40 requests across bursts of 8, 16 and 24 consumed **no jars at
all**, with a 24-concurrent burst finishing in 2s.

The allowance is not a fixed number. Measured the same day on the same code at 1 call, then at
2-34, then at 45+, so budgeting against a constant would have been wrong in both directions.
A jar that has stopped answering never recovers: it was still refused after three separate
120-second silences, while a fresh jar worked at the same moment. So the refusal is a count
rather than a penalty, and it is keyed to the session rather than the address - fresh jars
succeed consecutively from one IP.

What does *not* buy anything, all measured: slowing down (gaps of 0.3s to 10s, randomised
2.5-5s as upstream paces), real clicks instead of the keystroke poke, booting on
`/title/<hid>` instead of `/browse`, or letting 120s pass. The site's own `v` input flag reads
`0` on the successful request and on the refused one, so the refusal is not that counter.

Solved jars are written to disk under `WAF_JAR_STORE` and reloaded at startup, so a restart
inside the ~25 minutes a clearance is good for comes back warm - that covers a redeploy or a
crash. It survives `docker restart` on its own; mount a volume over `WAF_JAR_STORE` to also
survive a rebuild, which replaces the container. A request whose client has already given up is
abandoned rather than finished, since a jar and a page load are committed by then.

Loading an HTML page is free - only the API call is charged - and responses Cloudflare can
serve from its edge (`x-cache: HIT`) never reach the origin.

### What this can and cannot keep up with

While jars are being reused, FlareSolverr is off the critical path entirely. It matters only
when the site has withdrawn an allowance, and then its capacity is the ceiling: about **3
solves at once**, each ~11s - measured at 1, 2 and 3 concurrent succeeding in 11-12s, the
fourth failing, and six taking 23s for *less* throughput than three. Asking for more just
builds a queue inside FlareSolverr, where entries past the front hit their own `maxTimeout`
and are failed outright. So `WAF_JAR_BUFFER` (stock to keep) is deliberately separate from
`WAF_SOLVE_CONCURRENCY` (how hard FlareSolverr is driven).

In that degraded mode the ceiling is ~0.25 requests/second. Raising client timeouts does not
move it, because the work cannot be done faster - only more FlareSolverr instances, or a
longer cache TTL to cut the demand, will.

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

- `POST /request` with `{"path", "qs"}` — the one that matters. Returns `{"json": "<body>"}`,
  plain JSON, exactly as the site's own client reads it. `path` and `qs` are reissued
  through the bundle rather than replayed, because a captured `{"e": ...}` envelope cannot
  be decoded on its own: the bundle exposes no decoder, only the client that unwraps what
  it just received. Results are cached for `ORACLE_CACHE_TTL_MS`.
- `GET /sign?path=${api_path}&qs=${canonical_query}` — returns `{"token"}`. `qs` arrives
  already canonicalized by the client and is used verbatim.
- `POST /decrypt` — `410`. Kept only to explain why envelopes cannot be decoded offline.
- `GET /cookies` — the jar currently in use, for inspection. It is spent by definition:
  requests take their own.
- `GET /health` — liveness plus oracle counters (`signs`, `decrypts`, `rebuilds`, cache
  hit/miss) and jar buffer depth.

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
| `ORACLE_READY_TIMEOUT_MS` | `45000` | how long to wait for the bundle to publish its API client |
| `ORACLE_EVAL_TIMEOUT_MS` | `20000` | per-call evaluation budget |
| `ORACLE_MAX_ATTEMPTS` | `3` | attempts per request; each one costs a fresh jar |
| `ORACLE_POOL_SIZE` | `4` | pages in flight at once, each on its own jar |
| `ORACLE_REUSE_MAX` | `50` | requests one jar serves before being replaced regardless |
| `ORACLE_CACHE_TTL_MS` | `900000` | how long a body is reused before it is fetched again |
| `WAF_JAR_BUFFER` | `20` | jars solved ahead of time |
| `WAF_SOLVE_CONCURRENCY` | `3` | solves in flight at once — FlareSolverr's capacity, not the buffer depth |
| `WAF_JAR_STORE` | `/app/.jars` | where solved jars are kept across a restart |
| `WAF_JAR_MIN_LIFE_MS` | `300000` | don't keep or hand out a jar with less life than this |

404/400/422 are not retried: the site's answer about a path will not change, and a retry
costs a jar.

## The client side

The `comix-challenge.patch` file in this repository is the client-side half: the
changes to the Comix Tachiyomi/Suwayumi extension that make it talk to this
server. Note that it is stale: it predates `/request` and the flattened response
shapes. The live client changes are on the `comix-proxy` branch of the extension
repository, where the extension posts `{path, qs}` to `/request` and reads plain
JSON back.

## Disclaimer

This project interacts with the public comix.to web/API surface. The clearance
handling is for interoperability with an API the extension client is already
entitled to use. Use at your own discretion.
