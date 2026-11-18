[![Build Docker image](https://github.com/memories169/TuiFFVpn/actions/workflows/build-docker.yml/badge.svg)](https://github.com/memories169/TuiFFVpn/actions/workflows/build-docker.yml)

# 🦊 Firefox VPN Web Console

**Repo:** [github.com/memories169/TuiFFVpn](https://github.com/memories169/TuiFFVpn)

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

## Native desktop app — Linux · Windows · macOS (Catppuccin Macchiato)

fxvpn-desktop là **app native** (Gio UI, không Electron/webview) chạy
**cùng một engine Go** với web console trên cả 3 nền tảng — token keeper,
rotator, MASQUE dialer, SOCKS5 — nhưng in-process, **không cần Docker và
không có màn hình đăng nhập admin**:

- Tab **Trạng thái** — trạng thái tunnel, kết nối lại/ngắt, test nhanh
- Tab **Account** — thêm account (đăng nhập + 2FA hoặc dán token), danh sách
  không giới hạn, **🔄 refresh token tất cả**, đổi account đang dùng, xoá
- Tab **Vị trí** — danh sách country → city → server, bấm để kết nối
- Tab **Test** — exit-IP/latency/edge diagnostics qua tunnel
- Theme **Catppuccin Macchiato** toàn bộ widget; footer hiển thị thông báo
  tiếng Việt (⚠ Fastly tạm thời ≠ ⛔ token chết, đúng như web console)

```bash
make                 # Linux — cần libxkbcommon/wayland/x11/gl dev headers
make cpu             # Linux — không có Vulkan/GPU
# Windows: go build -tags nometal -o fxvpn-desktop.exe ./webui/desktop/cmd/fxvpn-desktop
# macOS:   go build -o fxvpn-desktop ./webui/desktop/cmd/fxvpn-desktop (cần Xcode CLT)
```

Bản dựng sẵn cho cả 3 nền tảng (linux-amd64/arm64 + AppImage, windows-amd64,
macos-amd64/arm64) do GitHub Actions tạo tại
[Releases](https://github.com/memories169/TuiFFVpn/releases).

Chi tiết cài đặt: Linux [docs/desktop-linux.md](docs/desktop-linux.md) (theo distro)
· Docker: [docs/install-docker.md](docs/install-docker.md)
· Windows (native): [docs/install-windows.md](docs/install-windows.md)
· macOS (native): [docs/install-macos.md](docs/install-macos.md)

#### Sign-in bị Fastly chặn? Dùng userscript trong Firefox thật

Chromium profile temp mà app mở đôi khi bị Fastly CAPTCHA 406 (TLS
fingerprint "lạnh"). Khi đó dùng `scripts/fxvpn-desktop-grabber.user.js`
(Tampermonkey/Violentmonkey trong **Firefox thật của bạn** — TLS thật =
edge cho qua): đăng nhập `accounts.firefox.com` bình thường, script tự
**đổi OAuth ngay trên máy** rồi **copy access/refresh vào clipboard** →
dán vào form **"Thêm bằng token"** trong app (email + access + refresh).
Đây là đường duy nhất hoạt động khi IP bị Fastly CAPTCHA-lock, vì chỉ
request từ browser thật mới qua được edge. Bản này riêng cho app
desktop; bản cho container là `scripts/fxvpn-pc-grabber.user.js` (đẩy
thẳng vào console qua HTTP).

State file mặc định `state.json` đặt **cạnh file binary/exe của app**
(layout portable — di chuyển thư mục app là dữ liệu đi theo). Cùng schema
với container, trỏ `--state` vào file của container để dùng lại account
có sẵn.

## Admin security & tabs

The web console requires an **admin login** first. Bootstrap credentials are
`admin` / `admin`. You can change the password in the **Cài đặt (Settings)** tab.

After logging in you get three tabs:

- **Quản lý account** — add as many Firefox accounts as you like (email+password,
  browser capture, manual tokens, or the PC userscript) — **no cap on the
  account count**: the state file, rotator, token keeper, and quota probes all
  scale with the list. Each account keeps its own OAuth tokens and quota.
  Click **“Dùng account này”** on any account to make it the one the proxy
  uses — if a server is already selected, the proxy restarts on the new
  account immediately. The account marked **● đang dùng** is active.
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

### Automatic re-connect on container restart

The selected server persists in `state.json`, and on boot the console
**automatically reconnects** the proxy to it: it runs the full healing chain
(refresh expired tokens, activate the entitlement if needed, fetch a fresh
proxy pass) and starts the SOCKS5 listener before the first rotation pass.
Failures (e.g. Fastly CAPTCHA on the token refresh from this network) are
logged and the UI keeps the last selection — re-selecting the server in the
Chọn location tab retries with the same chain once tokens are healthy.

### Token keeper — why non-active accounts stay valid

Firefox Accounts refresh tokens decay when their grant/session goes
unused: accounts added but never exercised go "token invalid" within
days while the last-used account stays fine. A background **token
keeper** runs every 24 hours and refreshes **every** account's access
token (skipping the active one — the rotator owns it), plus one
healing pass 20 seconds after boot for accounts that went stale while
the container was down.

The keeper refreshes accounts **concurrently** (`FXVPN_KEEPER_WORKERS`,
default 4): the whole list heals in one pass no matter how many accounts
you store, so account #100 no longer waits behind #1–#99 while its token
decays. Each account's refresh is gated per account — a slow or dead
account never blocks the others.

Failures are split into two very different kinds, both shown in the UI:

- ⚠ **Transient (Fastly anti-bot / network)** — `fastly anti-bot challenge`,
  connection resets, 5xx/429. Fastly serves the container's IP a CAPTCHA it
  cannot solve automatically; **the account is fine and the VPN keeps
  working** (token refresh is only needed hours later, and the edge block
  usually clears in minutes). Shown as an amber warning, retried
  automatically (one spaced retry per refresh, then again on the next
  keeper/rotation pass), and NEVER treated as a dead account — the rotator
  does not switch away from an account whose refresh merely hit the wall.
- ⛔ **Dead grant** — a clean HTTP 400/401/403 from FxA: the account's
  session was destroyed server-side (password change, sign-out everywhere).
  Shown in red on that account only; re-adding the account is the fix, and
  every other account keeps rotating normally.

You can also refresh every account's tokens **manually**: the
**“🔄 Refresh token tất cả account”** button in the account tab runs a
keeper pass on demand (active account included, same worker pool, one pass
at a time) and per-account ✓/⚠/⛔ states update live in the list.

### Automatic rotation

A background rotator runs every 30 minutes (`FXVPN_ROTATE_INTERVAL`) and:
1. **Refreshes** the active account's access token when it is within 30
   minutes of expiring (`FXVPN_REFRESH_BEFORE`; Firefox VPN tokens live
   ≤ 6h).
2. **Rotates** when the refresh fails (token revoked) or when the active
   account's quota drops below 512 MB — it walks the healthy accounts
   (most remaining quota first) until one yields a working proxy pass,
   with no manual step and no cap on the fallback depth: every usable
   account is a candidate, in order.

Additionally, the proxy pass itself is refreshed **in-band**: Guardian proxy
passes are short-lived (about an hour), and when the MASQUE edge answers
CONNECT with **401** the dialer re-fetches a fresh pass through the Guardian
chain (activate → refresh → retry) and retries the connection once — the
proxy keeps running without user intervention and the
`connect refused (HTTP 401)` errors from earlier versions are gone.

Access-token refreshes are equally automatic: every refresh path (rotator,
proxy-pass healing, ingest probe, account switch) funnels through a
per-account single-flight gate. Firefox Accounts refresh tokens are
**one-time-use (rotating)** — each successful refresh revokes the presented
token and issues a new one — so concurrent refreshes using the same token
would race and the loser would store a now-revoked refresh token. The gate
serializes refreshes **of the same account** while letting different
accounts refresh in parallel (the old global lock made account #50 wait for
#1's exchange — with many accounts the queued tokens decayed and died).
Refresh tokens only die permanently when the account changes password,
signs out everywhere, or the session lapses — those require re-adding the
account, and the failure reason shows on that account in the UI.

### Stable exit IP

SOCKS5 connections multiplex over a small pool of persistent MASQUE edge
sessions (utls + HTTP/2; up to 8 sessions, 32 concurrent tunnels each —
the same shape as sing-box's upstream session pool, which FoxyVPN uses as
its tunnel engine). Mozilla's edge farm maps each upstream session to a
NAT egress, so a fresh session per connection would rotate the exit IP on
every connection. Sessions with in-flight tunnels are **never** torn down;
idle-empty ones are pruned after 2 minutes, and the keepalive loop pings
every session every 45 s even with no active streams (Mozilla edges reap
idle sessions after a few minutes).

Session hygiene mirrors sing-box: before reusing a session idle for more
than 25 s, the dialer pings it — a zombie session fails the ping and is
replaced synchronously, so a CONNECT never stalls inside a half-dead
session. The session's busy counter covers **in-flight handshakes** too
(reserved before the CONNECT starts, released on tunnel close) — keepalive
and pruning therefore never reap a session whose CONNECT is still
negotiating, which previously surfaced as `io: read/write on closed pipe`
under concurrent load.

Pass renewal without session churn mirrors FoxyVPN's
`credentialDeadlineMillis`: the pass deadline is capped at **5 minutes**
regardless of the JWT exp claim, and the renewal loop replaces the pass
~60 s before that deadline through the dialer's atomic `UpdatePass` —
sessions are never touched (`session=retained`, like the reference
client's `adoptPass → UpdateToken` path). Every stage logs
(`pass renewal scheduled/starting/failed/renewed`).

**Account rotation also swaps the pass, not the sessions**: the rotator
switches accounts by fetching the new account's pass and calling
`UpdatePass` on the live dialer — the edge host is account-agnostic, so
the same sessions keep serving traffic with the new account's pass.
Tearing the pool down on rotation (an earlier behavior) killed every
sing-box flow on each 30-minute rotation; the pass-swap keeps flows
alive, and the in-band 401 refresh chain covers a pass the edge rejects
later.

Sessions also carry an **age cap** (10 minutes — the operaproxy lesson:
nothing long-lived can break mid-use): older sessions stop taking new
tunnels and are pruned once drained. Mozilla edges invalidate long-lived
h2 sessions server-side after a while (NAT/flow-state expiry — observed
after hours); without the cap the first CONNECT after that server-side
kill hit a closed pipe, and a same-session retry would be poisoned too.
Rotation before death lands the edge's kill on an already-drained session
instead of live traffic. Test connection's session-reset retry drops the
**whole pool** unconditionally — a server-invalidated session can look
healthy client-side, so retaining "busy" sessions would poison the retry;
live flows on a dead session are already broken and sing-box reconnects
instantly.

The CONNECT handshake itself is bounded with a 12-second budget inside the
dialer by racing the CONNECT against a timer — a session that stalls (edge
accepted the stream but never answers — occasionally seen right after
switching edges) fails fast and the dialer retries once on a
guaranteed-fresh session. The budget must NOT live in the request context:
x/net/http2 ties the tunnel stream's whole lifetime to `req.Context()`, so
canceling a handshake context after the headers would kill the tunnel with
`context canceled` on every subsequent read (a real regression this codebase
hit and fixed by the race pattern). The keepalive loop never tears down a
session with tunnels in flight (a failed liveness ping is tolerated while
traffic is active — h2 streams keep flowing), and Test connection resets
the edge session and retries once before surfacing an error.

Tunnel streams reject deadlines (`SetDeadline` et al. return an error,
mirroring the reference client): h2 CONNECT streams have no per-stream
deadlines, and a close-based deadline watchdog corrupted subsequent
operations on the same tunnel (`io: read/write on closed pipe`) when the
outer transport's generous per-operation deadlines expired on
slow-but-healthy tunnels. Stalls are handled at their proper layers — the
dialer's handshake race, session keepalive pings, the age cap, and the
caller's `Client.Timeout`.

**Edge-side rejection is a different failure**: when two consecutive
attempts with brand-new sessions fail fast (~200 ms, `closed pipe` right
after a 2xx CONNECT), the edge host itself is accepting the CONNECT and
then resetting the inner stream — a server-side rejection of this
edge+pass combination. Test connection marks the edge `edge_suspect` and
the UI says so; the fix is picking a different server from the same city.
No client-side change can help, and the same pass usually works on other
edges of the same city.

Session hygiene mirrors sing-box (which FoxyVPN uses as its tunnel engine):
before reusing a session idle for more than 25 s, the dialer pings it — a
zombie session fails the ping and is rebuilt synchronously, so a CONNECT
never stalls inside a half-dead session. Concurrent tunnels per session
are capped at 32 (sing-box's default `max_concurrent_streams`); beyond the
cap, dials rotate onto a fresh session.

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
  `FXVPN_INGEST_KEY` in docker-compose.yml. On the **desktop app** the key
  is auto-generated ONCE and persisted in `state.json` (tab Logs shows a
  copyable banner) — it no longer changes on restart, so the userscript
  only needs it pasted once.
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

## Deploy with Docker Compose

The recommended path uses the prebuilt GHCR image — no local build needed:

```bash
git clone https://github.com/memories169/TuiFFVpn.git
cd TuiFFVpn

cp docker-compose.yml.example docker-compose.yml
cp .env.example .env
# set FXVPN_INGEST_KEY (openssl rand -hex 24) and match it in the userscript
$EDITOR .env

docker compose up -d
# then open http://localhost:9090 (default admin password: admin — change it
# in the Cài đặt tab on first login)
```

To build the image yourself instead, remove the `image:` line's GHCR value
and add `build: .` to the service in your `docker-compose.yml` (requires
Go 1.20+ if you build outside Docker), or run:

```bash
docker build -t fxvpn-webui:local .
go build -o fxvpn-webui ./webui/cmd/fxvpn-webui   # or run directly
./fxvpn-webui -http :9090 -socks 127.0.0.1:1080 -state /data/state.json
```

### Docker image

The image ships only the Go binaries — the token capture runs in your own
browser via the userscript, so there is no browser stack inside:

1. `cp docker-compose.yml.example docker-compose.yml && cp .env.example .env`,
   set `FXVPN_INGEST_KEY` in `.env` (see the userscript section above), then
   `docker compose up -d` and open `http://localhost:9090` (admin/`admin`).
2. Install `scripts/fxvpn-pc-grabber.user.js` in your browser.
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
| | `FXVPN_ROTATE_INTERVAL` | `30m` | How often the rotator evaluates the active account |
| | `FXVPN_REFRESH_BEFORE` | `30m` | Refresh the active token when it expires within this window |
| | `FXVPN_KEEPER_INTERVAL` | `24h` | How often every account's refresh token is exercised |
| | `FXVPN_KEEPER_WORKERS` | `4` | Concurrent keeper refreshes (scales with your account count) |

### Edge control API (for sing-box / telegram & discord bots)

Traffic uses the single SOCKS5 port; server switching is a control-plane
operation. An external orchestrator — e.g. a telegram/discord bot driving
sing-box on another machine (a super-bot-go fork carries the client side
in its own repo) — manages ffvpn's server selection through three
key-authenticated endpoints (header `X-Ingest-Key`, the same secret the
userscript uses):

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/edges` | full server list from Remote Settings + current selection + proxy state |
| `POST` | `/api/edges/select` | switch server — body `{"country_code","country_name","city_code","city_name","server_host","server_port"}`; runs the same healing chain as the web UI and restarts the proxy on the new edge. The sing-box outbound (single `:1080`) needs **no change** |
| `GET` | `/api/edges/status` | current selection, proxy state, `edge_suspect` flag |

sing-box itself only ever sees one outbound — the ffvpn SOCKS5 listener.
The bot lists edges → `select` by name → reads status/exit IP; the bot-side
client lives in the bot's own repository, not here.

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

```
webui/
├── cmd/
│   ├── fxvpn-webui/        # container web console entry point
│   └── fxvpn-token/        # token capture helper
├── internal/               # engine internals (fxa, guardian, proxy, state, webapp)
├── bridge/                 # supported embedding API (used by the desktop app)
└── desktop/                # native Linux GUI (Gio, Catppuccin Macchiato)
    └── cmd/fxvpn-desktop/
docs/                       # per-platform install guides
Makefile                    # make / make cpu / make headless (compile-check)
```

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
| `webui/bridge` | embedding API over the engine (desktop app entry) |
| `webui/desktop` | native Linux GUI (Gio widgets, Macchiato theme) |

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

### Kiểm tra bản image đang chạy (tránh stale image)

Tab **Logs** trong web console luôn có dòng đầu dạng
`fxvpn-webui <version> http=... socks=...`. Version cũng hiện trong tiêu đề
trang. Nếu không thấy tính năng mới (Logs tab, UDP), image container đang
cũ — chạy:

```bash
docker compose build   # hoặc: docker compose up -d --build
docker compose up -d
```

`docker-compose.yml` đã set `pull_policy: build` nên `up -d` tự build lại
từ source checkout — miễn là bạn đã `git pull` trước.

## Torrents & UDP

Tunnel MASQUE của Mozilla (fastly-masque, port 2499) hỗ trợ **CONNECT-UDP
(RFC 9298)** — đã probe trực tiếp: `GET /.well-known/masque/udp/` trả
"405 method not allowed", tức route tồn tại và chỉ nhận extended CONNECT.
fxvpn giờ dùng nó để chuyển tiếp UDP:

- **HTTP/HTTPS trackers**: qua SOCKS5 CONNECT (TCP) như trước.
- **UDP trackers, DHT, DNS**: qua SOCKS5 UDP ASSOCIATE → CONNECT-UDP —
  datagram được đóng gói thành HTTP Datagram capsules trên cùng edge
  session với TCP (cùng exit IP, cùng pass rotation).
- WebRTC/QUIC qua CONNECT-UDP cũng đi được trong phạm vi datagram ≤64KB.

Cấu hình torrent client (qBittorrent) khi dùng fxvpn:

1. Tools → Options → Connection → Proxy server: `SOCKS5`, `127.0.0.1:1080`;
   tick **"Use proxy for peer connections"** — để toàn bộ traffic (kể cả
   UDP) đi qua tunnel, không rò IP thật.
2. Tracker `udp://` giờ hoạt động qua relay; nếu một tracker cụ thể vẫn
   lỗi, đó có thể là edge của server đó — thử chọn server khác.
3. Nếu gặp lỗi ở tab Logs kèm "CONNECT-UDP session failed",edge có thể
   đã đổi proto — cập nhật bản fxvpn mới hơn.
