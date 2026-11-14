// ==UserScript==
// @name         Firefox VPN Token Grabber (PC)
// @namespace    fxvpn
// @version      4.8.1
// @license      GPL-3.0-only
// @description  Bắt sessionToken từ Firefox Accounts (tự redirect sang context Firefox Desktop Sync để đăng ký VPN free cho account mới), tự đổi OAuth và đẩy vào container. Có escape hatch khi trang bị treo.
// @author       you
// @match        https://accounts.firefox.com/*
// @match        https://*.accounts.firefox.com/*
// @match        https://api.accounts.firefox.com/*
// @match        https://oauth.accounts.firefox.com/*
// @match        *://vpn.mozilla.org/*
// @match        *://*.vpn.mozilla.org/*
// @run-at       document-start
// @noframes
// @grant        GM_xmlhttpRequest
// @grant        GM_addStyle
// @connect      api.accounts.firefox.com
// @connect      oauth.accounts.firefox.com
// @connect      127.0.0.1
// @connect      localhost
// ==/UserScript==

(function () {
  'use strict';

  // ==== CẤU HÌNH ============================================================
  // URL của fxvpn-webui trong container (thay nếu chạy host/port khác).
  var CONSOLE_URL = 'http://127.0.0.1:9090';
  // FXVPN_INGEST_KEY đã set trong docker-compose.yml của container.
  var INGEST_KEY = '';
  // true = tự đổi token + đẩy vào container ngay khi bắt được.
  var AUTO_SEND = true;
  // Đặt false nếu trang accounts.firefox.com bị treo do redirect sync-context
  // (hoặc mở https://accounts.firefox.com/settings — redirect không chạy ở đó).
  var ENABLE_SYNC_REDIRECT = true;
  // (Tùy chọn) Cloudflare Worker relayer — giống hệt relayer/worker.js của
  // FoxyVPN gốc. Khi Fastly chặn IP/ASN mạng bạn (406 dai dẳng kể cả 4G),
  // request đi qua egress IP của Cloudflare (edge network, trusted) sẽ pass.
  // Deploy: xem relayer/README.md trong repo FoxyVPN, dán worker.js vào
  // Cloudflare Workers, rồi dán URL worker vào đây. Bỏ trống = đi trực tiếp.
  var RELAYER_URL = '';
  // ==========================================================================

  var SESSION_HEX = /^[0-9a-f]{64}$/;
  var CLIENT_ID = '5882386c6d801776';
  var SCOPE = 'profile https://identity.mozilla.com/apps/vpn';
  var PROTO = 'identity.mozilla.com/picl/v1/';
  var API = 'https://api.accounts.firefox.com/v1';
  // Edge chỉ chấp nhận UA Firefox trên các OAuth endpoint (đã verify: cookie
  // không cần, chỉ UA). GM_xmlhttpRequest chạy ngoài trang nên không bị CSP
  // chặn, và header UA này được forward nguyên vẹn.
  var FIREFOX_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0';
  var PANEL_ID = 'fxvpn-session-panel';
  var captured = null; // { token, email, uid, source, oauth }

  // ---- WebChannel hook (Firefox thật) + localStorage fallback (Chromium) ----
  // WebChannel "browser chrome" masquerade (FoxyVPN's WebView mechanism):
  // the sync-desktop page asks the "browser" via WebChannelMessageToChrome;
  // a real Firefox answers via WebChannelMessageToContent. Without a reply
  // the page never completes the desktop-sync handoff and Guardian
  // /activate can't provision the free tier for new accounts. We answer
  // exactly once per request with the same messageId.
  var CHANNEL_ID = 'account_updates';
  var replied = Object.create(null); // messageId -> true

  function sendToContent(command, data, messageId) {
    var envelope = {
      id: CHANNEL_ID,
      message: { command: command, data: data, messageId: messageId },
    };
    var detail = navigator.userAgent.toLowerCase().indexOf('fxios') !== -1
      ? envelope
      : JSON.stringify(envelope);
    var evt = new CustomEvent('WebChannelMessageToContent', { detail: detail });
    window.dispatchEvent(evt);
    document.dispatchEvent(evt);
  }

  function handleChannel(detail) {
    if (!detail) return;
    var envelope = detail;
    if (typeof envelope === 'string') {
      try { envelope = JSON.parse(envelope); } catch (e) { return; }
    }
    if (!envelope) return;
    // Only messages addressed to the browser channel.
    if (envelope.id && envelope.id !== CHANNEL_ID) return;
    var message = envelope.message || envelope;
    if (typeof message === 'string') {
      try { message = JSON.parse(message); } catch (e) { return; }
    }
    if (!message || !message.command) return;
    var command = String(message.command);
    var data = message.data || message.params || {};
    var msgId = String(message.messageId || envelope.messageId || '');

    // Capture login handoffs (the goal of the script).
    var token = String(data.sessionToken || data.token || '').trim().toLowerCase();
    if (token && SESSION_HEX.test(token) &&
        (command === 'fxaccounts:login' || command === 'fxaccounts:oauth_login' || /login/i.test(command))) {
      onSessionToken(token, data.email || '', data.uid || '', command);
    }

    // Masquerade replies (idempotent per messageId).
    if (msgId && !replied[msgId]) {
      replied[msgId] = true;
      if (command === 'fxaccounts:fxa_status') {
        sendToContent('fxaccounts:fxa_status', {
          capabilities: { engines: [], multiService: false, pairing: false },
          signedInUser: null,
        }, msgId);
      } else if (command === 'fxaccounts:can_link_account') {
        sendToContent('fxaccounts:can_link_account', { ok: true }, msgId);
      } else if (command === 'fxaccounts:pair_supplicant_metadata') {
        sendToContent(command, {}, msgId);
      }
    }
  }

  function attachChannelHook() {
    var onEvt = function (e) { try { handleChannel(e && e.detail); } catch (err) {} };
    window.addEventListener('WebChannelMessageToChrome', onEvt, true);
    document.addEventListener('WebChannelMessageToChrome', onEvt, true);
  }

  function pollLocalStorage() {
    try {
      var accounts = JSON.parse(localStorage.getItem('__fxa_storage.accounts') || '{}');
      var uidRaw = localStorage.getItem('__fxa_storage.currentAccountUid');
      var uid = uidRaw ? JSON.parse(uidRaw) : '';
      var entry = accounts[uid] || Object.values(accounts)[0];
      if (entry && entry.sessionToken && SESSION_HEX.test(entry.sessionToken)) {
        onSessionToken(entry.sessionToken, entry.email || '', entry.uid || '', 'localStorage');
      }
    } catch (e) {}
  }

  // ---- Panel -----------------------------------------------------------------
  function esc(s) {
    return String(s).replace(/[&<>"]/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c];
    });
  }

  function buildPanel() {
    if (!document.body || document.getElementById(PANEL_ID)) return;
    GM_addStyle(
      '#' + PANEL_ID + '{position:fixed;right:12px;top:12px;z-index:2147483647;width:430px;' +
      'background:#0f1222;color:#eef;border:1px solid #333;border-radius:10px;padding:12px;' +
      'font:13px/1.45 system-ui,sans-serif;box-shadow:0 6px 20px rgba(0,0,0,.5)}' +
      '#' + PANEL_ID + ' button{cursor:pointer;border:0;border-radius:6px;padding:6px 10px;color:#fff}' +
      '#' + PANEL_ID + ' textarea{width:100%;box-sizing:border-box;background:#1a1f36;color:#8fffb0;' +
      'border:1px solid #333;border-radius:6px;padding:6px;font:11px monospace}' +
      '#' + PANEL_ID + ' .st{font-size:12px;color:#9aa0b5;margin:6px 0}'
    );
    var div = document.createElement('div');
    div.id = PANEL_ID;
    div.innerHTML =
      '<div style="display:flex;justify-content:space-between;align-items:center">' +
      '<b style="color:#8fffb0">🦊 fxvpn token (PC)</b>' +
      '<button id="' + PANEL_ID + '-x" style="background:none;color:#fff">×</button></div>' +
      '<div class="st" id="' + PANEL_ID + '-st">đang chờ đăng nhập / token…<br><span style="font-size:11px">Account mới: hãy đăng nhập tại trang này (script đã tự mở URL với context Firefox Desktop Sync để account được đăng ký VPN miễn phí).</span></div>' +
      '<textarea id="' + PANEL_ID + '-out" rows="7" readonly></textarea>' +
      '<div style="display:flex;gap:8px;margin-top:8px">' +
      '<button id="' + PANEL_ID + '-retry" style="flex:1;background:#0060df">Đổi token lại</button>' +
      '<button id="' + PANEL_ID + '-copy" style="flex:1;background:#4d8dff">Copy JSON</button>' +
      '</div>';
    document.body.appendChild(div);
    document.getElementById(PANEL_ID + '-x').onclick = function () { div.remove(); };
    document.getElementById(PANEL_ID + '-retry').onclick = function () {
      if (captured && captured.token) exchangeOnPC(captured.token, captured.email);
      else setStatus('chưa có token — đăng nhập hoặc reload trang.');
    };
    document.getElementById(PANEL_ID + '-copy').onclick = function () {
      var el = document.getElementById(PANEL_ID + '-out');
      el.select();
      if (navigator.clipboard) navigator.clipboard.writeText(el.value);
    };
  }

  function setStatus(html) {
    var el = document.getElementById(PANEL_ID + '-st');
    if (el) el.innerHTML = html;
  }

  function setOutput(obj) {
    var el = document.getElementById(PANEL_ID + '-out');
    if (el) el.value = JSON.stringify(obj, null, 2);
  }

  // ---- Capture -----------------------------------------------------------------
  function onSessionToken(token, email, uid, source) {
    if (captured && captured.token === token) return;
    captured = { token: token, email: email, uid: uid, source: source, oauth: null };
    buildPanel();
    if (AUTO_SEND) exchangeOnPC(token, email);
    else setStatus('bắt được sessionToken — bấm “Đổi token lại”.');
  }

  // ---- WebCrypto helpers -------------------------------------------------------
  function hkdfID(tokenHex) {
    var raw = new Uint8Array(32);
    for (var i = 0; i < 32; i++) raw[i] = parseInt(tokenHex.substr(i * 2, 2), 16);
    return crypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveBits'])
      .then(function (key) {
        return crypto.subtle.deriveBits({
          name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0),
          info: new TextEncoder().encode(PROTO + 'sessionToken')
        }, key, 256);
      })
      .then(function (bits) {
        return Array.from(new Uint8Array(bits)).map(function (b) {
          return b.toString(16).padStart(2, '0');
        }).join('');
      });
  }

  function b64url(buf) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(buf)))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function makePKCE() {
    var verifier = b64url(crypto.getRandomValues(new Uint8Array(32)));
    return crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
      .then(function (h) { return { verifier: verifier, challenge: b64url(h) }; });
  }

  function gmFetch(opts) {
    return new Promise(function (resolve, reject) {
      GM_xmlhttpRequest(Object.assign({}, opts, {
        onload: function (r) { resolve(r); },
        onerror: function () { reject(new Error('network error')); },
        ontimeout: function () { reject(new Error('timeout')); },
        timeout: 30000,
      }));
    });
  }

  // Gọi 1 endpoint FxA. Khi RELAYER_URL được cấu hình, request đi qua worker:
  //   <worker>/?url=<base64 or encoded target>
  // Worker strip header nhạy cảm (x-forwarded-*...), giữ UA Firefox, thêm
  // Access-Control-Allow-Origin — y hệt relayer/worker.js của FoxyVPN gốc.
  function fxaFetch(method, url, headers, data) {
    var h = {};
    if (headers) {
      Object.keys(headers).forEach(function (k) {
        h[k] = headers[k];
      });
    }
    if (RELAYER_URL) {
      return gmFetch({
        method: method,
        url: RELAYER_URL.replace(/\/$/, '') + '/?url=' + encodeURIComponent(url),
        data: data,
        headers: h,
      });
    }
    return gmFetch({ method: method, url: url, data: data, headers: h });
  }

  // ---- OAuth flow trong GM_xmlhttpRequest (UA Firefox header) -------------------
  // Retry với backoff: Fastly chặn theo "bot score" của IP/ASN — soft-block
  // thường tự nhả sau vài giây đến vài phút.
  async function exchangeOnPC(token, email, attempt) {
    attempt = attempt || 1;
    var maxAttempts = 5;
    try {
      setStatus('tính HKDF/PKCE…');
      var res = await Promise.all([hkdfID(token), makePKCE()]);
      var bearerID = res[0];
      var pkce = res[1];
      var state = b64url(crypto.getRandomValues(new Uint8Array(16)));

      // ---- Bước 1: authorization ----
      setStatus('bước 1/2 — xin authorization code (lần ' + attempt + '/' + maxAttempts + ')…');
      var r1 = await fxaFetch('POST', API + '/oauth/authorization', {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        // Edge chỉ chấp nhận UA Firefox. GM forward header này trên Firefox;
        // trên Chromium một số manager bỏ qua — vẫn thử.
        'User-Agent': FIREFOX_UA,
        'Authorization': 'Bearer fxs_' + bearerID,
      }, JSON.stringify({
        client_id: CLIENT_ID,
        response_type: 'code',
        scope: SCOPE,
        state: state,
        access_type: 'offline',
        code_challenge: pkce.challenge,
        code_challenge_method: 'S256',
      }));
      var t1 = String(r1.responseText || '');
      // Phân loại nguồn lỗi: Mozilla trả {"code":..,"errno":..}; worker/HTTP
      // framework khác trả shape riêng (vd {"error":"Not found"} của
      // Vercel/Netlify hoặc worker chưa lưu code).
      var mozillaShaped = t1.indexOf('errno') !== -1 || t1.indexOf('"code"') !== -1 || t1.trim() === '';
      if (r1.status === 406) {
        if (attempt < maxAttempts) {
          var delay = attempt * 8000; // 8s, 16s, 24s, 32s
          setStatus('<b style="color:#f59e0b">Fastly chặn (406)</b> — tự thử lại sau ' + (delay / 1000) + 's (lần ' + (attempt + 1) + '/' + maxAttempts + ')…<br>Mẹo nhanh: tắt VPN/proxy hoặc chuyển mạng (4G) là hết ngay.');
          await new Promise(function (resolve) { setTimeout(resolve, delay); });
          return exchangeOnPC(token, email, attempt + 1);
        }
        throw new Error('Fastly chặn (406) sau ' + maxAttempts + ' lần — bot-score của IP/ASN mạng bạn. Cấu hình RELAYER_URL (Cloudflare Worker) ở đầu script rồi bấm “Đổi token lại”.');
      }
      if (r1.status === 404 && !mozillaShaped) {
        throw new Error('Relayer trả 404 ' + t1.slice(0, 100) + ' — worker của bạn KHÔNG chạy code fxvpn-relayer. Kiểm tra: (1) mở URL worker trên trình duyệt phải thấy {"status":"ok","relay":"foxyvpn"}; (2) nếu thấy 404/default page → code chưa được lưu, vào Edit Code dán lại fxvpn-relayer-worker.js rồi Deploy; (3) nếu bạn deploy trên Vercel/Netlify thì worker.js gốc là code Cloudflare Workers, phải dùng Cloudflare.');
      }
      if (r1.status === 401) {
        throw new Error('sessionToken bị từ chối (401) — session hết hạn hoặc cần verify. Đăng nhập lại accounts.firefox.com rồi bấm “Đổi token lại”.');
      }
      if (r1.status !== 200) {
        throw new Error('authorization HTTP ' + r1.status + ': ' + t1.slice(0, 140));
      }
      var auth = JSON.parse(t1);
      if (!auth.code) throw new Error('authorization response thiếu code');
      if (auth.state !== state) throw new Error('state mismatch');

      // ---- Bước 2: token exchange ----
      setStatus('bước 2/2 — đổi code lấy OAuth token…');
      var r2 = await fxaFetch('POST', API + '/oauth/token', {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'User-Agent': FIREFOX_UA,
      }, JSON.stringify({
        client_id: CLIENT_ID,
        grant_type: 'authorization_code',
        code: auth.code,
        code_verifier: pkce.verifier,
      }));
      var t2 = String(r2.responseText || '');
      if (r2.status === 406) {
        if (attempt < maxAttempts) {
          var delay2 = attempt * 8000;
          setStatus('<b style="color:#f59e0b">Fastly chặn bước 2 (406)</b> — tự thử lại sau ' + (delay2 / 1000) + 's…');
          await new Promise(function (resolve) { setTimeout(resolve, delay2); });
          return exchangeOnPC(token, email, attempt + 1);
        }
        throw new Error('Fastly chặn bước token (406) sau ' + maxAttempts + ' lần — cấu hình RELAYER_URL rồi bấm “Đổi token lại”.');
      }
      if (r2.status !== 200) {
        if (t2.indexOf('172') !== -1) throw new Error('code hết hạn (172) — bấm “Đổi token lại”.');
        throw new Error('token HTTP ' + r2.status + ': ' + t2.slice(0, 140));
      }
      var tok = JSON.parse(t2);
      if (!tok.access_token) throw new Error('token response thiếu access_token');

      captured.oauth = tok;
      var result = {
        email: email,
        access_token: tok.access_token,
        refresh_token: tok.refresh_token || '',
        expires_in: tok.expires_in || 0,
        session_token: token,
      };
      setStatus('<b style="color:#8fffb0">đã đổi xong OAuth tokens ✓</b>' + (email ? ' — ' + esc(email) : ''));
      setOutput(result);
      pushToContainer(result);
    } catch (err) {
      setStatus('<b style="color:#ff6b6b">lỗi:</b> ' + esc(String(err.message || err)));
      setOutput({ session_token: token, email: email, error: String(err.message || err) });
    }
  }
  // ---- Đẩy vào container ---------------------------------------------------------
  function pushToContainer(payload) {
    setStatus('đang gửi vào container…');
    gmFetch({
      method: 'POST',
      url: CONSOLE_URL.replace(/\/$/, '') + '/api/ingest',
      data: JSON.stringify(payload),
      headers: Object.assign(
        { 'Content-Type': 'application/json' },
        INGEST_KEY ? { 'X-Ingest-Key': INGEST_KEY } : {}
      ),
    }).then(function (r) {
      var body = {};
      try { body = JSON.parse(r.responseText || '{}'); } catch (e) { body = { error: (r.responseText || '').slice(0, 200) }; }
      if (r.status === 200) {
        setStatus('<b style="color:#8fffb0">xong ✓ container đã lưu OAuth tokens</b>' + (payload.email ? ' — ' + esc(payload.email) : ''));
        setOutput(body);
      } else if (/invalid ingest key/i.test(body.error || '')) {
        setStatus('<b style="color:#ff6b6b">INGEST_KEY sai</b> — đối chiếu FXVPN_INGEST_KEY (compose) với INGEST_KEY (script).');
        setOutput(body);
      } else {
        setStatus('<b style="color:#ff6b6b">container lỗi (HTTP ' + r.status + '):</b> ' + esc((body.error || '').slice(0, 180)));
        setOutput(body);
      }
    }).catch(function (err) {
      setStatus('<b style="color:#ff6b6b">không gọi được container</b> — kiểm tra CONSOLE_URL (' + esc(String(err.message || err)) + ')');
    });
  }

  // ---- Sync-context đăng ký (quan trọng cho account mới) ---------------------
  // FoxyVPN mở WebView với context=fx_desktop_v3&service=sync: FxA đăng ký
  // account như một login Firefox Desktop Sync. Account chỉ đăng nhập qua
  // trang accounts.firefox.com thường (không service context) KHÔNG được
  // Guardian /activate provision được — phải vào vpn.mozilla.org tay.
  //
  // Redirect CHỈ khi: (1) đang ở trang đăng nhập trơn của accounts.firefox.com
  // (path / hoặc /signin…), (2) chưa đăng nhập vào account nào trong browser
  // này, (3) chưa redirect lần nào trong tab. Sau khi đã có account trong
  // localStorage thì tuyệt đối không redirect (tránh bounce sau sign-in).
  var SYNC_LOGIN_URL = 'https://accounts.firefox.com/?context=fx_desktop_v3&service=sync&action=email';

  function hasStoredAccount() {
    try {
      var accounts = JSON.parse(localStorage.getItem('__fxa_storage.accounts') || '{}');
      return Object.keys(accounts).length > 0;
    } catch (e) {
      return false;
    }
  }

  function ensureSyncContext() {
    if (!ENABLE_SYNC_REDIRECT) return;
    if (location.hostname !== 'accounts.firefox.com') return;
    if (location.search.indexOf('context=fx_desktop_v3') !== -1) return;
    // Chỉ redirect ở các trang đăng nhập; không đụng /settings, /oauth, /pair…
    var path = location.pathname;
    var isLoginPage = path === '/' || path.indexOf('/signin') === 0 || path.indexOf('/signup') === 0;
    if (!isLoginPage) return;
    // Đã đăng nhập account nào trong browser này → không redirect nữa.
    if (hasStoredAccount()) return;
    // User đang giữa một flow riêng (code/email verification...) → không đụng.
    var q = location.search;
    if (q.indexOf('code=') !== -1 || q.indexOf('email=') !== -1 ||
        (q.indexOf('action=') !== -1 && q.indexOf('action=email') === -1)) {
      return;
    }
    if (sessionStorage.getItem('fxvpnRedirected') === '1') return; // tránh vòng lặp
    sessionStorage.setItem('fxvpnRedirected', '1');
    location.replace(SYNC_LOGIN_URL);
  }

  // ---- MAIN-world UA override ------------------------------------------------
  // FxA chỉ chạy WebChannel handshake (fxa_status → fxaccounts:login) khi
  // navigator.userAgent chứa "firefox" (isProbablyFirefox()). Trên Chromium/
  // Helium, phải override UA của TRANG (main world, không phải isolated world
  // của userscript). Tiêm <script> tại document-start, trước khi page JS đọc UA.
  function overridePageUA() {
    if (location.hostname !== 'accounts.firefox.com') return;
    var overrideFn = function () {
      try {
        var ffUA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0';
        Object.defineProperty(navigator, 'userAgent', { get: function () { return ffUA; }, configurable: true });
        Object.defineProperty(navigator, 'appVersion', { get: function () { return '5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0'; }, configurable: true });
        Object.defineProperty(navigator, 'vendor', { get: function () { return ''; }, configurable: true });
        Object.defineProperty(navigator, 'platform', { get: function () { return 'Win32'; }, configurable: true });
      } catch (e) {}
    };
    // Try unsafeWindow first (main world when the manager supports it).
    try {
      if (typeof unsafeWindow === 'object' && unsafeWindow && unsafeWindow.navigator) {
        var w = unsafeWindow;
        var ffUA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0';
        Object.defineProperty(w.navigator, 'userAgent', { get: function () { return ffUA; }, configurable: true });
        Object.defineProperty(w.navigator, 'appVersion', { get: function () { return '5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0'; }, configurable: true });
        Object.defineProperty(w.navigator, 'vendor', { get: function () { return ''; }, configurable: true });
        Object.defineProperty(w.navigator, 'platform', { get: function () { return 'Win32'; }, configurable: true });
        return;
      }
    } catch (e) {}
    // Fallback: inline script element (may be blocked by CSP 'script-src self').
    try {
      var script = document.createElement('script');
      script.textContent = '(' + overrideFn.toString() + ')();';
      (document.documentElement || document).appendChild(script);
      script.remove();
    } catch (e) {}
  }

  // ---- init ----------------------------------------------------------------------
  overridePageUA();
  ensureSyncContext();
  attachChannelHook();
  setInterval(pollLocalStorage, 1500);
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', buildPanel);
  } else {
    buildPanel();
  }
})();
