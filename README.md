[![Build Docker image](https://github.com/memories169/TuiFFVpn/actions/workflows/build-docker.yml/badge.svg)](https://github.com/memories169/TuiFFVpn/actions/workflows/build-docker.yml)

# 🦊 Firefox VPN Web Console

A **web UI** to log in with a Firefox account and pick a VPN server/location,
backed by a real Go engine that runs a local SOCKS5 proxy over the selected
Firefox VPN server. It is based on the architecture of the
[`firefox-vpn-client`](https://github.com/UjuiUjuMandan/firefox-vpn-client)
reference project (FxA login → Guardian proxy pass → Remote-Settings server
list → HTTP/2 CONNECT data plane), re-implemented here from the documented
public APIs.

```
browser ──► :9090 (Web console)
             │  login (email/password + email 2FA)
             │  pick country → city → server
             ▼
       SOCKS5 proxy on :1080 ──► Firefox VPN server (HTTP/2 CONNECT, Bearer proxy pass) ──► internet
```

## What it does

- **Log in** with your Firefox account (email + password, then the 6-digit code
  emailed to you when 2FA is required). The password is stretched with
  PBKDF2+HKDF into an `authPW`; the raw password is never sent.
- **Pick a location**: the server list is fetched live from Mozilla Remote
  Settings and shown as a country → city → server tree. You select a
  server and the proxy starts against it.
- **Runs the proxy**: the SOCKS5 listener on `:1080` dials destinations through
  the chosen Firefox VPN server using HTTP/2 CONNECT with the Guardian proxy
  pass. No `/dev/net/tun`, no root, no privileged container.
- **Persists** your OAuth tokens and the selected server to a state file
  (`0600`, atomic write), so a restart reuses them.

## Admin security & tabs

The web console requires an **admin login** first. Bootstrap credentials are
`admin` / `admin`. You can change the password in the **Cài đặt (Settings)** tab.

After logging in you get three tabs:

- **Quản lý account** — add as many Firefox accounts as you like (email+password,
  browser capture, manual tokens, or the PC userscript). Each account keeps its
  own OAuth tokens and quota. Click **“Dùng account này”** on any account to
  make it the one the proxy uses — if a server is already selected, the proxy
  restarts on the new account immediately. The account marked **● đang dùng**
  is active.
- **Chọn location** — pick a country → city → server; selecting one starts the
  SOCKS5 proxy against it **for the active account**. Switching accounts later
  keeps the same server and just re-opens the tunnel with the other account's
  proxy pass.
- **Cài đặt** — switch the theme (light/dark) and change the admin password.

### Automatic activation for new accounts

Adding a brand-new Firefox account works like FoxyVPN without touching
vpn.mozilla.org — but it needs the **Firefox-desktop masquerade**, which is
the actual mechanism inside FoxyVPN's WebView (`BrowserLoginScreen.kt` +
`FirefoxAccountHeaders.kt`):

1. The WebView's user agent is a **Firefox UA**, so FxA's
   `isProbablyFirefox()` passes and the page starts the WebChannel
   handshake (`fxaccounts:fxa_status` → `fxaccounts:can_link_account`).
2. The app **answers those messages itself** (as Firefox desktop would),
   so the page completes the desktop-sync handoff and fires
   `fxaccounts:login` — which the app captures.
3. FxA then records the sign-in as an **active Firefox-desktop Sync login**,
   and Guardian `POST /api/v1/fpn/activate` provisions the free-tier
   entitlement for the account. Without this registration the activate call
   answers **403** forever, and a manual vpn.mozilla.org visit was the only
   workaround.

The PC userscript (v4.8+) reproduces all three steps in a desktop browser:
it overrides `navigator.userAgent` in the page's JS world (main world via
`unsafeWindow`, with an inline-script fallback), redirects plain login URLs
to the `fx_desktop_v3` sync context, and answers `fxa_status` /
`can_link_account` WebChannel messages exactly once per request.

After the tokens land in the container, a background probe mirrors the app's
`fetchUserInfo` flow against Guardian:

1. `GET /api/v1/fpn/token` — fetch the proxy pass + quota headers.
2. On 401/403 → refresh the access token with the account's refresh token and
   retry (Firefox VPN tokens live ≤ 6h).
3. Still rejected → `POST /api/v1/fpn/activate` — provisions the free-tier
   entitlement for the account — then fetch the pass again.
4. If the pass still fails but `GET /api/v1/fpn/status` answers 200, the
   entitlement is recorded so the account shows as usable.

The rotator runs the same healing path every 30 minutes, and every manual
account switch does too, so a newly added account converges to a working
proxy pass without manual activation.

### Automatic rotation

A background rotator runs every 30 minutes and:
1. **Refreshes** the active account's access token when it is within 30
   minutes of expiring (Firefox VPN tokens live ≤ 6h).
2. **Rotates** to the other account with the most remaining quota when the
   refresh fails (token revoked) or when the active account's quota drops
   below 512 MB — the proxy restarts on the new account with no manual step.

Token ingestion also self-heals: when the just-pushed access token is rejected
by Guardian (e.g. it was already near expiry), the container refreshes it with
the account's refresh token, provisions the entitlement via Guardian
`/activate` for first-time accounts, and retries the quota probe.

The account list, per-account tokens, and the active account live in
`state.json` (`accounts` + `active_account`); legacy single-account state
files migrate automatically on first load.

## Getting Firefox VPN tokens

FxA's Fastly edge blocks plain HTTP clients with a CAPTCHA, and the
email/password flow hits the same wall. The reliable path is to let a real
browser sign in and read the token from the page's own WebChannel, which is
exactly what the FoxyVPN Android client does inside its WebView.

### How FoxyVPN gets the `sessionToken`

`app/src/main/java/com/vauth/foxyvpn/ui/screens/BrowserLoginScreen.kt` loads
`https://accounts.firefox.com/?context=fx_desktop_v3&service=sync&action=email`
in a WebView with a Firefox UA. A document-start script listens for the
`WebChannelMessageToChrome` DOM event and reads `message.data.sessionToken`
from the `fxaccounts:login` / `fxaccounts:oauth_login` commands (validated as
64 hex chars), while answering `fxaccounts:fxa_status` /
`fxaccounts:can_link_account` on `WebChannelMessageToContent` so the page keeps
going. `FxaAuthRepository.completeBrowserLogin` then trades the token for OAuth
tokens and destroys the FxA session.

### Recommended: use the browser on your PC (no browser in the container)

`scripts/fxvpn-pc-grabber.user.js` (Tampermonkey/Violentmonkey — works on
Firefox, Chrome, Edge, Brave) captures the `sessionToken` from the Firefox
Accounts page and **exchanges it right in the userscript**, then pushes the
ready OAuth tokens to the console:

1. Capture: `fxaccounts:login` WebChannel message (real Firefox) plus
   `__fxa_storage.accounts` localStorage polling (works everywhere, including
   Chromium — relevant because Mozilla blocks userscript managers on their
   pages under Firefox).
2. Exchange: `GM_xmlhttpRequest` runs outside the page, so the page's CSP does
   not apply, and each request carries an explicit `User-Agent: Firefox/140.0`
   header — the FxA OAuth endpoints only verify the UA (verified live: no
   Fastly cookies involved), so Chrome/Edge users work fine.
   Flow: `POST /v1/oauth/authorization` (Bearer + PKCE) →
   `POST /v1/oauth/token` (authorization_code grant).
3. Push: the exchanged tokens go to the console's `POST /api/ingest`; the
   container just stores them.

Setup:

```yaml
# docker-compose.yml — enable the ingest endpoint
environment:
  FXVPN_INGEST_KEY: "change-me-to-a-long-random-string"
```

Install the userscript, then edit its header:

```js
var CONSOLE_URL = 'http://127.0.0.1:9090';   // container console
var INGEST_KEY  = 'change-me-to-a-long-random-string';
```

Sign in (or just open `accounts.firefox.com` while already signed in); the
panel appears top-right and runs the whole flow automatically.

Troubleshooting the PC path:

- **406 at either OAuth step, even after switching to 4G** — Fastly scores
  your IP/ASN and both your broadband and mobile carrier can be flagged. The
  reliable fix is the same one FoxyVPN itself ships: a **Cloudflare Worker
  relayer**. Deploy `relayer/worker.js` from the FoxyVPN repo (free, 5
  minutes — see `relayer/README.md`: create a Worker, paste the code, copy
  the `*.workers.dev` URL), then set it in the userscript header:

  ```js
  var RELAYER_URL = 'https://<worker>.<subdomain>.workers.dev';
  ```

  Requests then egress from Cloudflare's edge IPs, which Fastly trusts — the
  bot score of your local network no longer matters. Keep the URL private
  (it counts against your Worker's free quota).
- **Relayer answers 404 `{"error":"Not found"}`** — the deployment is not
  running the relayer code. This JSON shape comes from Vercel/Netlify
  (or an unsaved Cloudflare Worker), not from Mozilla. Verify by opening the
  worker URL in a browser: it must show `{"status":"ok","relay":"foxyvpn"}`.
  If not, re-paste `fxvpn-relayer-worker.js` in **Edit Code** and **Deploy**.
  The `worker.js` from FoxyVPN is **Cloudflare Workers** code — deploying it
  verbatim on Vercel/Netlify will not work.
- **401 "sessionToken bị từ chối"** — the session was revoked or needs
  step-up. Sign in again on accounts.firefox.com, then click
  “Đổi token lại”.
- **errno 172** — the code expired between the two steps; just retry.
- **"invalid ingest key"** — `INGEST_KEY` in the userscript must equal
  `FXVPN_INGEST_KEY` in docker-compose.yml.
- **"không gọi được container"** — CONSOLE_URL host/port wrong, or the
  console port is not published when the PC is a different machine.

### Pull the prebuilt image (GHCR)

CI publishes the image to GitHub Container Registry on every push to `main`
and on `v*` tags:

```bash
docker pull ghcr.io/memories169/tuiffvpn:latest
# or pin a release:
docker pull ghcr.io/memories169/tuiffvpn:1.0.0
```

The GHCR package is private by default if the repo is private — either make
the package public (Package settings → Change visibility) or run
`docker login ghcr.io` with a PAT that has `read:packages`.

## Build & run

Requires Go 1.20+.

```bash
# build and run with Docker
docker compose up --build
# then open http://localhost:9090

# or run directly
go build -o fxvpn-webui ./webui/cmd/fxvpn-webui
./fxvpn-webui -http :9090 -socks 127.0.0.1:1080 -state /data/state.json
```

### Docker image

The image ships only the Go binaries — the token capture runs in your own
browser via the userscript, so there is no browser stack inside:

1. `docker compose up --build`, open `http://localhost:9090` (admin/`admin`).
2. Set `FXVPN_INGEST_KEY` in docker-compose.yml (see the userscript section
   above) and install `scripts/fxvpn-pc-grabber.user.js` in your browser.
3. Sign in on `accounts.firefox.com` — tokens flow into the console
   automatically; the rotator keeps them fresh and switches accounts as
   quotas drain.

The CLI `fxvpn-token` is also in the image (`docker compose exec fxvpn-webui
/app/fxvpn-token --help`) for scripted token exchange.

### Configuration (flags / env)

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `-http` | `WEBUI_ADDR` | `:9090` | Web console listen address |
| `-socks` | `SOCKS_ADDR` | `127.0.0.1:1080` | SOCKS5 proxy listen address |
| `-state` | `STATE_FILE` | `/data/state.json` | Persisted tokens + selection |
| `-guardian` | `GUARDIAN_ENDPOINT` | `https://vpn.mozilla.org` | Guardian API endpoint |

## Web UI endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/login` | email/password → login (or `needs_2fa`) |
| `POST` | `/api/verify` | submit the emailed 2FA code |
| `GET` | `/api/servers` | country/city/server tree from Remote Settings |
| `POST` | `/api/select` | choose a server; fetch proxy pass; start SOCKS5 proxy |
| `GET` | `/api/status` | login, selected server, proxy state |
| `GET` | `/api/accounts` | list managed accounts + quota + which is active |
| `POST` | `/api/accounts/select` | switch the active account; restarts the proxy on it |
| `POST` | `/api/accounts/delete` | remove an account (stops the proxy if it was running on it) |
| `POST` | `/api/ingest` | PC-browser userscript pushes OAuth tokens (requires `FXVPN_INGEST_KEY`) |
| `POST` | `/api/login-token` | manually store OAuth tokens (fallback when FxA login is CAPTCHA-blocked) |
| `POST` | `/api/admin/login` | admin login (`admin`/`admin` by default) |
| `POST` | `/api/admin/logout` | end admin session |
| `GET` | `/api/admin/status` | admin auth + theme state |
| `POST` | `/api/admin/change-password` | change admin password |
| `POST` | `/api/admin/theme` | set light/dark theme |

## Layout

| Path | Responsibility |
|---|---|
| `webui/cmd/fxvpn-webui` | entrypoint / HTTP server |
| `webui/cmd/fxvpn-token` | standalone CLI: exchange a sessionToken for OAuth tokens |
| `webui/internal/webapp` | REST API handlers + embedded HTML/JS/CSS UI |
| `webui/internal/browsercapture` | browser-over-CDP helpers (sessionToken validation shared by the ingest fallback) |
| `webui/internal/fxa` | Firefox Accounts login, email 2FA, sessionToken → OAuth exchange, Fastly solver |
| `webui/internal/guardian` | Guardian proxy pass + entitlement |
| `webui/internal/serverlist` | Remote-Settings server tree |
| `webui/internal/proxy` | SOCKS5 listener + HTTP/2 CONNECT upstream |
| `webui/internal/state` | atomic JSON persistence |

## Honesty & authorized use

This is for **Firefox accounts you own or administer**. Login produces OAuth
tokens and a Guardian proxy pass for that account; the proxy relays traffic
through the account's VPN entitlement. It is an unofficial client that depends
on Mozilla's interface behavior and may need updates when Mozilla changes its
APIs. It is not a tool to obtain, share, or crack other people's Firefox VPN
subscriptions.

## Credits & prior art

This project exists thanks to the following open-source references:

- **[FoxyVPN](https://github.com/Vauth/FoxyVPN)** — the Android client this
  project re-implements for the desktop/web environment. Its source is the
  origin of nearly every mechanism here: the FxA WebChannel masquerade
  (`BrowserLoginScreen.kt`), the Firefox UA substitution
  (`FirefoxAccountHeaders.kt`), the Guardian healing chain
  (`GuardianClient.kt` — pass → activate → retry → status), the
  `MozillaVPN/*` control-plane headers, the PKCE session-token exchange, and
  the Fastly challenge solver design (`FastlyChallengeSolver.kt`).
- **[firefox-vpn-client](https://github.com/UjuiUjuMandan/firefox-vpn-client)
  (UjuiUjuMandan)** — an independent Go client for the same protocol. Its
  `cmd/proxy-demo` clarified the HTTP/2 CONNECT tunnel details (h2 session
  keep-alive, tunnel write buffering, exit verification with a real
  `http.Client` dialing through the tunnel) that this project's
  `webui/internal/proxy` mirrors.
- **Mozilla Firefox Accounts / Guardian** — the
  [fxa](https://github.com/mozilla/fxa) source tree was consulted to pin down
  the OAuth grant TTL (`FXA_EXPIRATION_ACCESS_TOKEN`), the WebChannel message
  envelope and the `fxa_status` default reply shape, and the
  `isProbablyFirefox()` gating that makes the desktop masquerade necessary.

All credit for the original protocol reverse-engineering belongs to the
FoxyVPN authors; this repository is a study/automation derivative for
personal account management.

## License

Licensed under the **GNU GPL-3.0** (see [LICENSE](LICENSE)) — any fork or
redistribution must remain open-source under the same terms.

Note on references: FoxyVPN (by Vauth) is MIT-licensed; this project contains
no code copied from it — only re-implemented mechanisms, credited above. The
MIT license of that project requires keeping its copyright notice in
redistributions of its own code, which does not apply here.

## Troubleshooting the tunnel

- **"tunnel connected but no exit IP returned; inner response: …"** — the
  CONNECT tunnel is up (your proxy pass JWT is valid!) but the inner stream
  did not return a Cloudflare trace. The snippet after the colon shows exactly
  what came back instead. Typical contents and their meaning:
  - `HTTP/1.1 400 … The plain HTTP request was sent to HTTPS port` — fixed
    in this version: the probe used to write plain HTTP/1.1 into the tunnel
    (and an intermediate fix passed `DialTLSContext` returning a raw conn,
    which skipped TLS too). The probe now uses a plain `http.Transport` whose
    `DialContext` dials through the tunnel, so `http.Transport` performs a
    real TLS handshake with `www.cloudflare.com` inside the tunnel — verified
    by the certificate check, which doubles as an integrity test of the whole
    tunnel path.
  - `(empty response …)` — the edge closed the inner stream immediately, most
    often a **quota-exhausted account** or a revoked entitlement. Check the
    account's remaining quota and switch to another account.
  - an HTML page — a captive portal or ISP hijack intercepting the inner
    request; complete the portal or change networks.
  - an HTTP error line — the inner target refused; retry another location.
- **"tunnel dial failed: parsing JWT failed"** — the edge rejected the proxy
  pass JWT. The pass lives ~a few hours; re-select the location to fetch a
  fresh one, or re-add the account (refresh flow) if it keeps failing.
- **"tunnel dial failed: connect refused (HTTP 400)"** — the edge refused the
  CONNECT; usually the same expired-pass cause (the body carries the precise
  edge error). The dialer also normalizes the `Proxy-Authorization` header
  (a historical double-`Bearer` bug is fixed in this version).
- **"proxy did not start: token invalid (HTTP 401)"** — the account's access
  token was rejected by Guardian. The account may not have an active VPN
  subscription, or the token expired; re-add the account via the userscript.
- **Edge servers** come from Mozilla Remote Settings
  (`*.m1.fastly-masque.net`, port 2499); quarantined ones are skipped.
