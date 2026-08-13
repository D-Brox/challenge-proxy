# challenge-proxy

Collection of proxy servers that offload site-specific challenge and DRM solving
from the Tachiyomi/Suwayomi extensions that consume them. Each proxy lives on its
own branch.

## Branches

- **[kagane-drm](https://github.com/D-Brox/challenge-proxy/tree/kagane-drm)** —
  Widevine DRM challenge proxy for the Kagane API. Requires a Widevine device file
  and FlareSolverr.

- **[comix-proxy](https://github.com/D-Brox/challenge-proxy/tree/comix-proxy)** —
  Signed-token and WAF challenge proxy for the comix.to API. Mints the required
  `_` token in pure Node, solves the site rotate captcha (`waf_pass`) and the
  Cloudflare challenge (`cf_clearance`) via FlareSolverr, and re-extracts the JS
  cipher material from the live site with Playwright when the extension detects a
  rotation.

## Usage

Check out the branch for the proxy you want and follow its README:

```
git clone https://github.com/D-Brox/challenge-proxy.git
git checkout <branch>
```

Each branch ships its own `docker-compose.yml` and listens on its own port.
