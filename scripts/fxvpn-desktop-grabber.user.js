// ==UserScript==
// @name         Firefox VPN Token Grabber (Desktop app)
// @namespace    fxvpn-desktop
// @version      1.0.1
// @license      GPL-3.0-only
// @description  Bắt sessionToken từ Firefox Accounts trong TRÌNH DUYỆT THẬT của bạn, tự copy vào clipboard, hiện trong panel. Dán vào app desktop (fxvpn-desktop) vào ô "Session token (từ đăng nhập browser)" rồi bấm "Đổi session thành token". Bản này KHÔNG dành cho container docker (bản đó là fxvpn-pc-grabber.user.js).
// @author       you
// @match        https://accounts.firefox.com/*
// @match        https://*.accounts.firefox.com/*
// @match        https://oauth.accounts.firefox.com/*
// @run-at       document-start
// @noframes
// @grant        GM_setClipboard
// @grant        GM_addStyle
// @grant        GM_xmlhttpRequest
// @connect      api.accounts.firefox.com
// @connect      127.0.0.1
// @connect      localhost
// @connect      oauth.accounts.firefox.com
// ==/UserScript==

/*
 * TẠI SAO CÓ BẢN NÀY
 * ------------------
 * Desktop app (fxvpn-desktop) tự mở Chromium profile temp để đăng nhập, và
 * Fastly edge trước FxA hay chặn các profile "lạ" như vậy bằng CAPTCHA 406.
 * Bản userscript cho container (fxvpn-pc-grabber.user.js) hoạt động được vì
 * nó chạy trong TRÌNH DUYỆT THẬT của bạn: TLS fingerprint thật, cookies thật,
 * IP quen thuộc — edge cho qua.
 *
 * Flow GIỐNG HỆT bản docker (và hơn): bắt token trong browser thật → đổi
 * OAuth ngay trên máy → LẤY CẢ PROXY PASS (/fpn/token + /activate) trong
 * browser → đẩy cả bộ vào app desktop qua localhost ingest (9091) →
 * bấm chọn server trong app là chạy, KHÔNG có call Go nào tới FxA/Guardian
 * để edge chặn. Copy clipboard vẫn giữ làm backup.
 *
 * KHÔNG dùng chung với bản container: script này không POST token đi đâu cả
 * (bản container đẩy token vào máy chủ qua HTTP; bản này copy token để dán
 * vào app desktop).
 */

(function () {
  'use strict';

  // ==== CẤU HÌNH ============================================================
  // true = script tự đổi OAuth NGAY TRÊN MÁY (2 request tới FxA với UA
  // Firefox thật) rồi TỰ ĐẨY vào app desktop qua localhost ingest — account
  // xuất hiện trong app không cần dán tay. Giữ true: nếu IP bị Fastly
  // CAPTCHA-lock thì đổi token TRONG APP cũng vô ích — chỉ request từ
  // browser thật mới qua được edge.
  var EXCHANGE_ON_PC = true;
  // URL ingest của app desktop — khớp flag --ingest / FXVPN_INGEST_ADDR
  // (mặc định 127.0.0.1:9091).
  var CONSOLE_URL = 'http://127.0.0.1:9091';
  // FXVPN_INGEST_KEY của app desktop. App SinH key một lần rồi LƯU VĨNH VIỄN
  // trong state.json — key KHÔNG ĐỔI qua các lần khởi động lại, nên bạn chỉ
  // cần dán key vào đây MỘT LẦN. Xem/copy key trong tab Logs của app
  // (banner "Ingest key (userscript)"). Lưu ý: nếu bạn từng set biến môi
  // trường FXVPN_INGEST_KEY thì key đó ưu tiên hơn và banner Logs vẫn hiện
  // giá trị đúng.
  var INGEST_KEY = '';
  // (Tùy chọn) Cloudflare Worker relayer — giống hệt relayer/worker.js của
  // FoxyVPN gốc / bản grabber cho container. Khi Fastly chặn IP/ASN mạng bạn
  // (406 dai dẳng), request đi qua egress IP của Cloudflare (trusted) sẽ
  // pass. Deploy: dán worker.js vào Cloudflare Workers rồi dán URL vào đây.
  // Bỏ trống = đi trực tiếp từ IP của bạn.
  var RELAYER_URL = '';
  // ==========================================================================

  var SESSION_HEX = /^[0-9a-f]{64}$/;
  var CLIENT_ID = '5882386c6d801776';
  var SCOPE = 'profile https://identity.mozilla.com/apps/vpn';
  var PROTO = 'identity.mozilla.com/picl/v1/';
  var API = 'https://api.accounts.firefox.com/v1';
  var GUARDIAN = 'https://vpn.mozilla.org';
  // Edge chỉ chấp nhận UA Firefox trên các OAuth endpoint. GM_xmlhttpRequest
  // forward header này nguyên vẹn — kể cả khi chạy trên Chromium.
  var FIREFOX_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0';
  var PANEL_ID = 'fxvpn-desktop-panel';
  var captured = null; // { token, email, uid, source, oauth }

  // ---- WebChannel hook ------------------------------------------------------
  // FxA giao token cho "browser" qua WebChannelMessageToChrome; hook nghe cả
  // hai kênh trên window + document (các build FxA khác nhau dùng kênh khác).
  var CHANNEL_ID = 'account_updates';
  var replied = Object.create(null);

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
    if (envelope.id && envelope.id !== CHANNEL_ID) return;
    var message = envelope.message || envelope;
    if (typeof message === 'string') {
      try { message = JSON.parse(message); } catch (e) { return; }
    }
    if (!message || !message.command) return;
    var command = String(message.command);
    var data = message.data || message.params || {};
    var msgId = String(message.messageId || envelope.messageId || '');

    // Bắt token (mục tiêu chính).
    var token = String(data.sessionToken || data.token || '').trim().toLowerCase();
    if (token && SESSION_HEX.test(token) &&
        (command === 'fxaccounts:login' || command === 'fxaccounts:oauth_login' || /login/i.test(command))) {
      onSessionToken(token, data.email || '', data.uid || '', command);
    }

    // Trả lời câu hỏi của trang (giả làm Firefox desktop) — idempotent.
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
    document.addEventListener('WebChannelMessageToContent', onEvt, true);
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

  // ---- XHR sniffer ------------------------------------------------------------
  // Phòng hờ: token cũng nằm trong body của POST /account/login (giống hook
  // trong app). Wrap INSTANCE không đụng prototype (tránh đệ quy với FxA).
  function sniff(text) {
    try {
      if (!text || typeof text !== 'string' || text.length > 100000) return;
      var body = JSON.parse(text);
      var tok = body.sessionToken || (body.data && body.data.sessionToken) || '';
      if (tok && SESSION_HEX.test(tok)) {
        onSessionToken(tok, body.email || '', body.uid || '', 'xhr:' + (body.grant_type || 'login'));
      }
    } catch (e) { /* không phải JSON login — bỏ qua */ }
  }

  function attachXHRSniffer() {
    var RealXHR = window.XMLHttpRequest;
    var onDone = function () {
      try {
        if (this.readyState === 4 && this.responseText) {
          var url = (this.responseURL || '') + '';
          if (url.indexOf('/account/login') !== -1 || url.indexOf('/oauth/') !== -1) {
            sniff(this.responseText);
          }
        }
      } catch (e) {}
    };
    window.XMLHttpRequest = function () {
      var xhr = new RealXHR();
      xhr.addEventListener('load', onDone);
      return xhr;
    };
    window.XMLHttpRequest.prototype = RealXHR.prototype;
    ['UNSENT', 'OPENED', 'HEADERS_RECEIVED', 'LOADING', 'DONE'].forEach(function (k) {
      try { window.XMLHttpRequest[k] = RealXHR[k]; } catch (e) {}
    });
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
      '<b style="color:#8fffb0">🦊 fxvpn token → app desktop</b>' +
      '<button id="' + PANEL_ID + '-x" style="background:none;color:#fff">×</button></div>' +
      '<div class="st" id="' + PANEL_ID + '-st">đang chờ đăng nhập / token…</div>' +
      '<textarea id="' + PANEL_ID + '-out" rows="6" readonly></textarea>' +
      '<div style="display:flex;gap:8px;margin-top:8px">' +
      '<button id="' + PANEL_ID + '-copy" style="flex:1;background:#0060df">📋 Copy token</button>' +
      '<button id="' + PANEL_ID + '-exch" style="flex:1;background:#4d8dff">Đổi token trên máy</button>' +
      '</div>' +
      '<div class="st" style="margin-top:6px">Token sau khi đổi được copy tự động — dán vào form “Thêm bằng token” của app desktop (email + access + refresh).</div>';
    document.body.appendChild(div);
    document.getElementById(PANEL_ID + '-x').onclick = function () { div.remove(); };
    document.getElementById(PANEL_ID + '-copy').onclick = function () {
      if (!captured || !captured.token) { setStatus('chưa có token nào.'); return; }
      var payload;
      if (captured.oauth) {
        payload = captured.email + '\n' + captured.oauth.access_token + '\n' + (captured.oauth.refresh_token || '');
      } else {
        payload = captured.token;
      }
      copyText(payload);
      setStatus('<b style="color:#8fffb0">đã copy ✓</b> — OAuth: email/access/refresh mỗi dòng một ô; session: 1 token.');
    };
    document.getElementById(PANEL_ID + '-exch').onclick = function () {
      if (captured && captured.token) exchangeOnPC(captured.token, captured.email);
      else setStatus('chưa có token — hãy đăng nhập trước.');
    };
  }

  function copyText(text) {
    // GM_setClipboard vượt qua mọi hạn chế clipboard của trang.
    try { GM_setClipboard(text, 'text/plain'); return; } catch (e) {}
    try { navigator.clipboard.writeText(text); } catch (e) {}
  }

  function setStatus(html) {
    var el = document.getElementById(PANEL_ID + '-st');
    if (el) el.innerHTML = html;
  }

  function setOutput(obj) {
    var el = document.getElementById(PANEL_ID + '-out');
    if (el) el.value = typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2);
  }

  // ---- Capture -----------------------------------------------------------------
  function onSessionToken(token, email, uid, source) {
    if (captured && captured.token === token) return;
    captured = { token: token, email: email, uid: uid, source: source, oauth: null };
    buildPanel();
    setStatus(
      '<b style="color:#8fffb0">bắt được sessionToken ✓ (' + esc(source) + ')</b>' +
      (email ? ' — ' + esc(email) : '') +
      '<br>đang đổi sang OAuth ngay trên máy này…'
    );
    if (EXCHANGE_ON_PC) exchangeOnPC(token, email);
    else setStatus('bắt được sessionToken — bấm “Đổi token trên máy”.');
  }

  // ---- Proxy pass ngay trong browser ------------------------------------------
  // Go-side fetches are 406'd; từ browser thật edge cho qua. Lấy pass JWT
  // (+quota headers) rồi đẩy cả bộ vào app — app không cần gọi Guardian.
  async function fetchProxyPass(accessToken, email, sessionToken, tok, attempt) {
    attempt = attempt || 1;
    var maxAttempts = 4;
    try {
      setStatus('lấy proxy pass (lần ' + attempt + '/' + maxAttempts + ')…');
      var r = await fxaFetch('GET', GUARDIAN + '/api/v1/fpn/token', {
        'Authorization': 'Bearer ' + accessToken,
        'Accept': 'application/json',
      });
      if (r.status === 406 && attempt < maxAttempts) {
        var delay = attempt * 8000;
        setStatus('<b style="color:#f59e0b">Fastly chặn pass (406)</b> — thử lại sau ' + (delay / 1000) + 's…');
        await new Promise(function (resolve) { setTimeout(resolve, delay); });
        return fetchProxyPass(accessToken, email, sessionToken, tok, attempt + 1);
      }
      var pass = null, qmax = '', qleft = '';
      if (r.status === 200) {
        var body = {};
        try { body = JSON.parse(r.responseText || '{}'); } catch (e) {}
        if (body.token) {
          pass = body.token;
          qmax = r.responseHeaders.match(/x-quota-limit:\s*([^\r\n]+)/i) ? RegExp.$1.trim() : '';
          qleft = r.responseHeaders.match(/x-quota-remaining:\s*([^\r\n]+)/i) ? RegExp.$1.trim() : '';
        }
      }
      if (!pass && (r.status === 401 || r.status === 403)) {
        // Chưa entitlement → activate (free tier) rồi thử lại một lần.
        setStatus('account chưa kích hoạt VPN — gọi /activate…');
        var ra = await fxaFetch('POST', GUARDIAN + '/api/v1/fpn/activate', {
          'Authorization': 'Bearer ' + accessToken,
          'Accept': 'application/json',
        });
        if (ra.status === 200 || ra.status === 201) {
          return fetchProxyPass(accessToken, email, sessionToken, tok, 1);
        }
        setStatus('<b style="color:#f59e0b">activate HTTP ' + ra.status + '</b> — vẫn đẩy token vào app; pass sẽ lấy lại khi edge thoáng.');
      }
      if (pass) {
        setStatus('<b style="color:#8fffb0">đã có proxy pass ✓</b>' + (email ? ' — ' + esc(email) : '') +
          '<br>đang đẩy bộ token + pass vào app desktop…');
      } else {
        setStatus('không lấy được pass (' + r.status + ') — đẩy token vào app; pass sẽ tự lấy lại khi edge thoáng.');
      }
      pushToApp({
        email: email,
        access_token: tok.access_token,
        refresh_token: tok.refresh_token || '',
        expires_in: tok.expires_in || 0,
        proxy_pass: pass || '',
        quota_max: qmax,
        quota_left: qleft,
      });
    } catch (err) {
      setStatus('<b style="color:#ff6b6b">lỗi lấy pass:</b> ' + esc(String(err.message || err)) + ' — đẩy token trước.');
      pushToApp({
        email: email,
        access_token: tok.access_token,
        refresh_token: tok.refresh_token || '',
        expires_in: tok.expires_in || 0,
      });
    }
  }

  // ---- Đẩy vào app desktop (localhost ingest) ---------------------------------
  function pushToApp(payload) {
    setStatus('đang gửi vào app desktop…');
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
        setStatus('<b style="color:#8fffb0">xong ✓ app desktop đã lưu OAuth tokens</b>' + (payload.email ? ' — ' + esc(payload.email) : ''));
        setOutput(body);
      } else if (/invalid ingest key/i.test(body.error || '')) {
        setStatus('<b style="color:#ff6b6b">INGEST_KEY sai</b> — mở tab Logs của app, copy key từ banner "Ingest key (userscript)" rồi dán vào INGEST_KEY ở đầu script này (key cố định, chỉ cần làm một lần).');
        setOutput(body);
      } else {
        setStatus('<b style="color:#ff6b6b">app lỗi (HTTP ' + r.status + '):</b> ' + esc((body.error || '').slice(0, 180)));
        setOutput(body);
      }
    }).catch(function (err) {
      setStatus('<b style="color:#ff6b6b">không gọi được app</b> — kiểm tra CONSOLE_URL (' + esc(String(err.message || err)) + ') và app có đang chạy không.');
    });
  }

  // ---- WebCrypto helpers (tái dùng logic bản grabber cho container) -----------
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

  // Gọi 1 endpoint FxA. Khi RELAYER_URL được cấu hình, request đi qua worker
  // (egress IP của Cloudflare — trusted bởi Fastly). UA Firefox header luôn
  // được set: GM forward nguyên vẹn, và edge chỉ nhìn UA.
  function fxaFetch(method, url, headers, data) {
    var h = { 'User-Agent': FIREFOX_UA };
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

  // ---- OAuth flow ngay trên máy (tùy chọn) ------------------------------------
  // Browser thật = TLS fingerprint thật → edge cho qua, không cần relayer.
  async function exchangeOnPC(token, email, attempt) {
    attempt = attempt || 1;
    var maxAttempts = 5;
    try {
      setStatus('tính HKDF/PKCE…');
      var res = await Promise.all([hkdfID(token), makePKCE()]);
      var bearerID = res[0];
      var pkce = res[1];
      var state = b64url(crypto.getRandomValues(new Uint8Array(16)));

      setStatus('xin authorization code (lần ' + attempt + '/' + maxAttempts + ')…');
      var r1 = await fxaFetch('POST', API + '/oauth/authorization', {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
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
      if (r1.status === 406) {
        if (attempt < maxAttempts) {
          var delay = attempt * 8000;
          setStatus('<b style="color:#f59e0b">Fastly chặn (406)</b> — tự thử lại sau ' + (delay / 1000) + 's (lần ' + (attempt + 1) + '/' + maxAttempts + ')…<br>Mẹo nhanh: tắt VPN/proxy hoặc chuyển mạng (4G) là hết ngay.');
          await new Promise(function (resolve) { setTimeout(resolve, delay); });
          return exchangeOnPC(token, email, attempt + 1);
        }
        throw new Error('Fastly chặn (406) sau ' + maxAttempts + ' lần — bot-score của IP/ASN mạng bạn. Cấu hình RELAYER_URL (Cloudflare Worker) ở đầu script (giống bản grabber cho container) rồi bấm “Đổi token trên máy”.');
      }
      if (r1.status === 401) {
        throw new Error('sessionToken bị từ chối (401) — session hết hạn hoặc chưa verify 2FA.');
      }
      if (r1.status !== 200) {
        throw new Error('authorization HTTP ' + r1.status + ': ' + t1.slice(0, 140));
      }
      var auth = JSON.parse(t1);
      if (!auth.code) throw new Error('authorization response thiếu code');
      if (auth.state !== state) throw new Error('state mismatch');

      setStatus('đổi code lấy OAuth token…');
      var r2 = await fxaFetch('POST', API + '/oauth/token', {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      }, JSON.stringify({
        client_id: CLIENT_ID,
        grant_type: 'authorization_code',
        code: auth.code,
        code_verifier: pkce.verifier,
      }));
      var t2 = String(r2.responseText || '');
      if (r2.status !== 200) {
        if (t2.indexOf('172') !== -1) throw new Error('code hết hạn (172) — bấm lại.');
        throw new Error('token HTTP ' + r2.status + ': ' + t2.slice(0, 140));
      }
      var tok = JSON.parse(t2);
      if (!tok.access_token) throw new Error('token response thiếu access_token');

      captured.oauth = tok;
      var pair = email + '\n' + tok.access_token + '\n' + (tok.refresh_token || '');
      copyText(pair);
      setStatus('<b style="color:#8fffb0">đã đổi OAuth ✓</b>' + (email ? ' — ' + esc(email) : '') +
        '<br>đang lấy proxy pass (trong browser — edge cho qua)…');
      setOutput({
        email: email,
        access_token: tok.access_token,
        refresh_token: tok.refresh_token || '',
        expires_in: tok.expires_in || 0,
        session_token: token,
      });
      fetchProxyPass(tok.access_token, email, token, tok, 1);
    } catch (err) {
      setStatus('<b style="color:#ff6b6b">lỗi đổi token:</b> ' + esc(String(err.message || err)));
    }
  }

  // ---- MAIN-world UA override ------------------------------------------------
  // FxA chỉ mở WebChannel handshake khi navigator.userAgent là Firefox. Trên
  // Chromium override UA của TRANG (main world); trên Firefox thật không cần
  // nhưng vẫn override an toàn (giữ nguyên giá trị Firefox).
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
    try {
      var script = document.createElement('script');
      script.textContent = '(' + overrideFn.toString() + ')();';
      (document.documentElement || document).appendChild(script);
      script.remove();
    } catch (e) {}
  }

  // ---- init ------------------------------------------------------------------
  overridePageUA();
  attachChannelHook();
  attachXHRSniffer();
  setInterval(pollLocalStorage, 1500);
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', buildPanel);
  } else {
    buildPanel();
  }
})();
