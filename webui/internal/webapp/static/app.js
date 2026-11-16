const $ = (id) => document.getElementById(id);
let countries = [];
let verifySession = null;

async function api(path, method, body) {
  const opts = { method: method || 'GET', headers: {} };
  if (body) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
  const r = await fetch('/api/' + path, opts);
  return r.json();
}

// ---- Bootstrap: check admin session, show login or app ----
(async function init() {
  const st = await api('admin/status');
  if (st.authenticated) {
    applyTheme(st.theme || 'light');
    showApp();
  }
  bindAdminForm();
})();

function bindAdminForm() {
  $('admin-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    $('admin-error').textContent = '';
    const res = await api('admin/login', 'POST', {
      user: $('admin-user').value, password: $('admin-pass').value,
    });
    if (res.ok) { showApp(); } else { $('admin-error').textContent = res.error || 'Login failed'; }
  });
  $('logout').addEventListener('click', async () => {
    await api('admin/logout', 'POST');
    // Reset to the admin login view immediately (not just on reload).
    $('app').classList.add('hidden');
    $('admin-login').classList.remove('hidden');
    $('admin-pass').value = '';
  });
}

function showApp() {
  $('admin-login').classList.add('hidden');
  $('app').classList.remove('hidden');
  bindTabs();
  loadAccounts();
  loadCountries();
  bindSettings();
  loadStatusTheme();
}

// ---- Tabs ----
function bindTabs() {
  document.querySelectorAll('.tab').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      document.querySelectorAll('.tabpanel').forEach((p) => p.classList.add('hidden'));
      $('tab-' + btn.dataset.tab).classList.remove('hidden');
    });
  });
}

// ---- Account management ----
$('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('login-error').textContent = '';
  const email = $('email').value, password = $('password').value;
  const res = await api('login', 'POST', { email, password });
  if (res.needs_2fa) { verifySession = res.session; $('verify-card').style.display = ''; return; }
  if (res.error) { $('login-error').textContent = res.error; return; }
  loadAccounts();
});

$('verify-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('verify-error').textContent = '';
  const res = await api('verify', 'POST', { session: verifySession, code: $('verify-code').value, email: $('email').value });
  if (res.error) { $('verify-error').textContent = res.error; return; }
  $('verify-card').style.display = 'none';
  loadAccounts();
});

$('token-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('token-error').textContent = '';
  const res = await api('login-token', 'POST', {
    access_token: $('tok-access').value,
    refresh_token: $('tok-refresh').value,
    email: $('tok-email').value,
  });
  if (res.error) { $('token-error').textContent = res.error; return; }
  $('tok-access').value = ''; $('tok-refresh').value = '';
  loadAccounts();
});

async function loadAccounts() {
  const res = await api('accounts');
  const list = $('account-list');
  list.innerHTML = '';
  const accts = res.accounts || [];
  // Số lượng account không bị giới hạn — hiển thị tổng số để theo dõi khi
  // danh sách dài.
  const counter = $('account-count');
  if (counter) counter.textContent = accts.length ? `${accts.length} account` : '';
  if (accts.length === 0) { list.innerHTML = '<li class="muted">Chưa có account nào — thêm qua form đăng nhập phía trên.</li>'; return; }
  accts.forEach((a) => {
    const li = document.createElement('li');
    li.className = 'account-item';
    const quota = a.quota_left === '' ? '?' : a.quota_left;
    const active = a.active;
    const span = document.createElement('span');
    // refresh_error = token CHẾT thật (HTTP 400/401/403: đổi mật khẩu,
    // sign-out) → ⛔ cần thêm lại account. probe_error chứa lỗi Fastly
    // tạm thời → ⚠ account vẫn hoạt động bình thường (VPN vẫn chạy), chỉ
    // là edge đang chặn IP server, sẽ tự retry.
    const isDead = a.has_token && a.refresh_error;
    const transient = !isDead && (a.probe_error || '').toLowerCase().includes('fastly') ||
                      !isDead && (a.probe_error || '').toLowerCase().includes('refresh:');
    span.innerHTML = `<b>${a.email}</b>${active ? ' <span class="active-badge">● đang dùng</span>' : ''}` +
      ` — Quota: ${quota} / ${a.quota_max || '?'}` +
      (a.has_token ? '' : ' <span class="muted">(chưa có token — bấm "Dùng account này" trên account khác, hoặc thêm lại account này)</span>') +
      (isDead ? ` <span class="dead-badge" title="${a.refresh_error.replace(/"/g, '&quot;')}">⛔ token chết: ${a.refresh_error.length > 90 ? a.refresh_error.slice(0, 90) + '…' : a.refresh_error}</span>` : '') +
      (transient ? ` <span class="warn-badge" title="${(a.probe_error || '').replace(/"/g, '&quot;')}">⚠ Fastly chặn tạm thời — account vẫn hoạt động bình thường</span>` : '') +
      (!isDead && !transient && a.probe_error ? ` <span class="muted" title="${a.probe_error.replace(/"/g, '&quot;')}">⚠ probe: ${a.probe_error.length > 90 ? a.probe_error.slice(0, 90) + '…' : a.probe_error}</span>` : '') +
      (a.refreshed_at && new Date(a.refreshed_at).getFullYear() > 2000 ? ` <span class="muted" title="Lần refresh token gần nhất bởi token keeper">✓ refresh ${new Date(a.refreshed_at).toLocaleString()}</span>` : '');
    if (active) li.classList.add('account-active');
    const use = document.createElement('button');
    use.type = 'button';
    use.textContent = active ? 'Đang dùng' : 'Dùng account này';
    use.className = 'small' + (active ? ' ghost' : '');
    if (active) use.disabled = true;
    use.addEventListener('click', async () => {
      use.disabled = true;
      use.textContent = 'Đang chuyển…';
      const res = await api('accounts/select', 'POST', { email: a.email });
      if (res.note) {
        // Chuyển thành công nhưng có lưu ý (failover/proxy chưa restart).
        alert('Chuyển account: ' + res.note);
      } else if (res.error) {
        use.textContent = 'Dùng account này';
        use.disabled = false;
        alert('Chuyển account: ' + res.error);
      }
      loadStatusTheme();
      loadAccounts();
    });
    const del = document.createElement('button');
    del.type = 'button';
    del.textContent = 'Xóa';
    del.className = 'ghost small';
    del.addEventListener('click', async () => {
      if (!confirm('Xóa account ' + a.email + '? Proxy đang chạy trên account này sẽ dừng.')) return;
      await api('accounts/delete', 'POST', { email: a.email });
      loadStatusTheme();
      loadAccounts();
    });
    li.appendChild(span);
    li.appendChild(use);
    li.appendChild(del);
    list.appendChild(li);
  });
}

// ---- Location ----
async function loadCountries() {
  const res = await api('servers');
  if (res.error) { $('country').innerHTML = '<option>' + res.error + '</option>'; return; }
  countries = res.countries || [];
  const sel = $('country');
  sel.innerHTML = '<option value="">Chọn quốc gia</option>' + countries.map((c) => `<option value="${c.code}">${c.name} (${c.code})</option>`).join('');
  sel.disabled = false;
  // Restore the persisted selection (server + account survive restarts).
  await restoreSelection();
}

// restoreSelection re-applies the saved country/city/server after a reload,
// and shows the active account + proxy state.
async function restoreSelection() {
  const st = await api('status');
  const selected = st.selected || {};
  if (selected.country_code) {
    const country = countries.find((c) => c.code === selected.country_code);
    if (country) {
      $('country').value = country.code;
      const cs = $('city');
      cs.innerHTML = '<option value="">Chọn thành phố</option>' +
        country.cities.map((ct) => `<option value="${ct.code}">${ct.name}</option>`).join('');
      cs.disabled = false;
      if (selected.city_code) {
        const city = country.cities.find((ct) => ct.code === selected.city_code);
        if (city) {
          cs.value = city.code;
          const ul = $('servers');
          ul.innerHTML = '';
          city.servers.forEach((srv) => {
            if (srv.quarantined) return;
            const li = document.createElement('li');
            const btn = document.createElement('button');
            const isCurrent = srv.hostname === selected.server_host;
            btn.textContent = srv.hostname + ':' + srv.port + (isCurrent ? '  ✓' : '');
            if (isCurrent) btn.classList.add('current-server');
            btn.addEventListener('click', () => pickServer(country, city, srv, btn));
            li.appendChild(btn);
            ul.appendChild(li);
          });
        }
      }
    }
  }
  // Proxy + account state line.
  const email = st.email || '(no account)';
  const proxy = st.proxy || {};
  const lines = [];
  lines.push(`Account active: ${email}`);
  if (selected.server_host) {
    lines.push(`Server: ${selected.server_host}:${selected.server_port}`);
    lines.push(proxy.running ? 'Proxy: đang chạy trên ' + a_proxyAddrFixed() : 'Proxy: chưa chạy — bấm server để khởi động lại');
  }
  $('selection-status').textContent = lines.join(' · ');
  if (proxy.running) {
    $('test-result').textContent = 'Proxy đang chạy (đã lưu). Bấm Test connection để kiểm tra exit IP.';
  }
}

function a_proxyAddrFixed() {
  return window.location.hostname + ':1080';
}

// pickServer handles the server button click (shared by fresh list and
// restored list).
async function pickServer(country, city, srv, btn) {
  const res = await api('select', 'POST', {
    country_code: country.code, country_name: country.name,
    city_code: city.code, city_name: city.name,
    server_host: srv.hostname, server_port: srv.port,
  });
  if (res.error) {
    btn.title = res.error;
    if (res.action === 're_add_account') {
      $('test-result').textContent = 'Lỗi: account đang chọn không có token. Hãy thêm lại account (userscript/form) rồi chọn lại server.\nChi tiết: ' + res.error;
      loadAccounts();
    } else {
      $('test-result').textContent = 'Lỗi khi chọn location: ' + res.error;
    }
    return;
  }
  $('test-result').textContent = `Đã chọn ${srv.hostname}:${srv.port} — proxy đang chạy. Bấm Test connection để kiểm tra exit IP.`;
  document.querySelectorAll('.server-list button').forEach((b) => b.classList.remove('current-server'));
  btn.classList.add('current-server');
}

$('country').addEventListener('change', (e) => {
  const code = e.target.value;
  const country = countries.find((c) => c.code === code);
  const cs = $('city');
  cs.innerHTML = '<option value="">Chọn thành phố</option>' + (country ? country.cities.map((ct) => `<option value="${ct.code}">${ct.name}</option>`).join('') : '');
  cs.disabled = !country;
  $('servers').innerHTML = '';
});

$('city').addEventListener('change', (e) => {
  const country = countries.find((c) => c.code === $('country').value);
  const city = country ? country.cities.find((ct) => ct.code === e.target.value) : null;
  const ul = $('servers');
  ul.innerHTML = '';
  if (!city) return;
  city.servers.forEach((srv) => {
    if (srv.quarantined) return;
    const li = document.createElement('li');
    const btn = document.createElement('button');
    btn.textContent = srv.hostname + ':' + srv.port;
    btn.addEventListener('click', () => pickServer(country, city, srv, btn));
    li.appendChild(btn);
    ul.appendChild(li);
  });
});

// ---- Connection test ----
$('test-conn').addEventListener('click', async () => {
  const btn = $('test-conn');
  btn.disabled = true;
  $('test-result').textContent = 'Đang kiểm tra…';
  const res = await api('test');
  if (res.ok) {
    let msg = 'Kết nối OK qua: ' + res.server + '\nExit IP: ' + res.exit_ip + ' (' + res.country + ')';
    if (res.edge_sessions != null) msg += '\nEdge sessions: ' + res.edge_sessions;
    if (res.second_ip) {
      msg += res.second_ip === res.exit_ip
        ? '\nIP ổn định giữa các tunnel trong session ✓'
        : '\n⚠ IP đổi giữa các tunnel trong cùng session: ' + res.exit_ip + ' → ' + res.second_ip;
    }
    msg += '\nĐộ trễ: ' + res.latency_ms + ' ms';
    $('test-result').textContent = msg;
  } else {
    let msg = 'Lỗi: ' + (res.error || 'test failed');
    if (res.edge_suspect) {
      msg += '\n⚠ Edge host này đang từ chối tunnel phía server (session mới liên tiếp bị RST sau 2xx).\n→ Chọn server KHÁC trong cùng thành phố — lỗi này không thể sửa từ client.';
    }
    $('test-result').textContent = msg;
  }
  btn.disabled = false;
});

// ---- Settings ----
async function loadStatusTheme() {
  const st = await api('admin/status');
  $('theme').value = st.theme || 'light';
  applyTheme(st.theme || 'light');
}

$('apply-theme').addEventListener('click', async () => {
  const theme = $('theme').value;
  const res = await api('admin/theme', 'POST', { theme });
  if (res.ok) { applyTheme(theme); }
});

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
}

$('pass-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('pass-error').textContent = '';
  const res = await api('admin/change-password', 'POST', { current: $('cur-pass').value, next: $('new-pass').value });
  if (res.ok) { $('pass-error').textContent = 'Đã đổi mật khẩu.'; $('cur-pass').value = ''; $('new-pass').value = ''; }
  else { $('pass-error').textContent = res.error || 'Đổi mật khẩu thất bại'; }
});

// ---- Refresh token tất cả account (thủ công) ----
// Gọi /api/accounts/refresh-all: server chạy nền một đợt refresh mọi
// account (giống token keeper). Lỗi Fastly tạm thời chỉ là ⚠; lỗi token
// chết thật mới là ⛔. Danh sách tự cập nhật trong lúc chạy; GET endpoint
// trả running để biết khi nào xong.
$('refresh-all').addEventListener('click', async () => {
  const btn = $('refresh-all');
  const status = $('refresh-all-status');
  btn.disabled = true;
  status.textContent = 'Đang bắt đầu…';
  try {
    const res = await api('accounts/refresh-all', 'POST', {});
    if (res.error) { status.textContent = 'Lỗi: ' + res.error; btn.disabled = false; return; }
    if (!res.started) {
      status.textContent = 'Một đợt refresh khác đang chạy — chờ nó xong nhé.';
      btn.disabled = false;
      return;
    }
    status.textContent = 'Đang refresh token của tất cả account… (xem ✓/⚠/⛔ trên từng account)';
    // Poll trạng thái: GET không khởi động đợt mới. Dừng khi running=false
    // (đợt vừa xong) hoặc sau 10 phút tối đa.
    const started = Date.now();
    const timer = setInterval(async () => {
      const st = await api('accounts/refresh-all'); // GET — chỉ đọc trạng thái
      await loadAccounts();
      if (!st.running || Date.now() - started > 10 * 60 * 1000) {
        clearInterval(timer);
        btn.disabled = false;
        status.textContent = st.running ? 'Vẫn đang chạy — kiểm tra log container nếu cần.' : 'Hoàn tất — danh sách đã cập nhật.';
        loadAccounts();
      }
    }, 4000);
  } catch (err) {
    status.textContent = 'Lỗi: ' + err;
    btn.disabled = false;
  }
});
