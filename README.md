# Comix Proxy server

This is a server to proxy signed-token and WAF challenge requests to the Comix API.
It mints the `_` token the API requires, solves the site's rotate captcha (`waf_pass`)
and the Cloudflare challenge (`cf_clearance`) via FlareSolverr, and re-extracts the
JS cipher material from the live site with Playwright when the extension detects a
material rotation.

Requires FlareSolverr to be running on port 8191 to pass the Cloudflare challenge.

## Usage

Clone the repository and navigate to it:

```
git clone https://github.com/D-Brox/challenge-proxy.git
cd challenge-proxy
git checkout comix-proxy
```

The easiest way to use this server is to run it with docker:
```
docker compose up -d
```

Or, if you prefer running it directly with Node 18+:
```
npm install
FLARESOLVERR_URL=http://localhost:8191/v1 node server.mjs
```

The server listens on `http://localhost:9191` by default.

## Endpoints

- `GET /sign?path=${api_path}&qs=${canonical_query}&force=1` — mints a signed `_` token for the API call and returns the current `cf_clearance`, `waf_pass` and `user_agent` to use with it.
- `GET /cookies?force=1` — returns the current `cf_clearance`, `waf_pass` and `user_agent` (used when a page is served a fresh captcha).
- `GET /material` — returns the current JS cipher material as `{"s":[...],"k":[...]}`.
- `POST /refresh-material` — re-extracts the cipher material from the live site with Playwright (triggered by the extension when a material rotation is detected).
- `POST /reload-material` — reloads the embedded material from `material.json` without re-extracting.
- `GET /decrypt?e=${envelope}` — decodes a signed API envelope.
- `GET /health` — simple liveness check.

## How it works

The comix.to API requires a per-request `_` token minted by obfuscated JS loaded in
the browser, and some responses come back wrapped in an `"e"` envelope. This proxy
runs the cipher in pure Node (`lib/cipher.js`) so the extension never needs to boot
a WebView for signing or decryption. The `cf_clearance` cookie is bound to the
user agent it was solved with, so the proxy returns its UA alongside the cookies
and the extension mirrors all three on its own requests.

The `comix-challenge.patch` file in this repository is the client-side half: the
changes to the Comix Tachiyomi/Suwayomi extension that make it talk to this
server (proxy preference, `/sign`-minted tokens, `/decrypt`-decoded envelopes,
mirrored `cf_clearance`/`waf_pass` cookies and UA). It applies to a local
`comix-challenge` branch created from that one extension repo:

```
git checkout -b comix-challenge
git apply --3way /path/to/challenge-proxy/comix-challenge.patch
```

## Disclaimer

This project interacts with the public comix.to web/API surface. The cipher material
and captcha solving are for interoperability with an API the extension client is
already entitled to use. Use at your own discretion.
