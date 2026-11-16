# Cài đặt — Linux desktop (fxvpn-desktop)

App native Linux (Gio UI, không Electron/webview/Chrome, theme **Catppuccin
Macchiato**) chạy engine Go trực tiếp trong tiến trình — **không cần Docker,
không cần web console, không có màn hình đăng nhập admin**. State file tương
thích 100% với bản container (`state.json` cùng schema): trỏ `--state` tới
file của container nếu muốn dùng lại account đã thêm.

---

## 1. Điều kiện

- Linux 64-bit (amd64/arm64) với session đồ họa **Wayland hoặc X11**
- **Go ≥ 1.21** (`go version` để kiểm tra)
- `git`, `make`, `gcc` (cgo cần gcc để link Wayland/X11/Vulkan)

## 2. Cài thư viện hệ thống

Chạy **một** khối lệnh đúng distro của bạn. Đây là các gói `-dev`/`-devel`
(headers + `.pc`), bản runtime thường đã có sẵn từ desktop environment.

### Debian / Ubuntu / Linux Mint / Pop!_OS / Kali

```bash
sudo apt-get update
sudo apt-get install -y build-essential git make \
  libxkbcommon-dev libwayland-dev libx11-dev libx11-xcb-dev \
  libgl-dev libegl-dev libgles2-dev libvulkan-dev
```

### Fedora / RHEL / CentOS Stream / Rocky / Alma

```bash
sudo dnf install -y golang git make gcc \
  libxkbcommon-devel wayland-devel libX11-devel libX11-xcb-devel \
  mesa-libGL-devel mesa-libEGL-devel mesa-libGLES-devel vulkan-loader-devel
```

### Arch / Manjaro / EndeavourOS / CachyOS

```bash
sudo pacman -S --needed go git make gcc \
  libxkbcommon wayland libglvnd mesa vulkan-icd-loader
```

### openSUSE (Tumbleweed/Leap)

```bash
sudo zypper install -y go git make gcc \
  libxkbcommon-devel wayland-devel libX11-devel \
  Mesa-libGL-devel Mesa-libEGL-devel vulkan-loader-devel
```

### NixOS

Thêm vào `environment.systemPackages` (hoặc `nix-shell` tạm):

```nix
environment.systemPackages = with pkgs; [
  go git pkg-config
  libxkbcommon wayland libGL mesa vulkan-loader
  xorg.libX11 xorg.libX11-xcb
];
```

(`nix-shell -p go git pkg-config libxkbcommon wayland libGL mesa vulkan-loader xorg.libX11`)

### Kiểm tra thư viện đã đủ

```bash
for p in xkbcommon wayland-client gl egl; do
  pkg-config --exists $p && echo "OK  $p" || echo "MISS $p"
done
# Mong đợi 4 dòng OK. Còn MISS → gói -dev tương ứng chưa được cài.
```

Vulkan là **tuỳ chọn** (chỉ để render GPU); thiếu vẫn build được với
`make cpu` ở bước 4.

## 3. Tải mã nguồn

```bash
git clone https://github.com/memories169/TuiFFVpn.git
cd TuiFFVpn
```

(Không dùng git: tải ZIP từ giao diện web, giải nén, `cd` vào thư mục.)

## 4. Build

```bash
make
```

Lệnh này tạo binary `./fxvpn-desktop` (~17 MB) — Wayland + X11 + GPU render.

Biến thể:

| Lệnh | Khi nào dùng |
|---|---|
| `make` | mặc định — đủ tất cả lib ở bước 2 |
| `make cpu` | máy không có/thiếu Vulkan (VM, driver cũ) — render qua GL/CPU |
| `make headless` | chỉ kiểm tra code compile (binary không mở được cửa sổ — dùng trong CI/container) |
| `make test` | chạy toàn bộ unit test của engine + GUI |
| `make vet` / `make fmt` | kiểm tra tĩnh / format |

Build lần đầu tải module Gio (khoảng 40 MB) — cần internet; lần sau dùng
cache, buildOffline thoải mái.

Go không ở PATH? Trỏ thẳng: `make GO=/usr/local/go/bin/go`.

## 5. Chạy

```bash
./fxvpn-desktop
```

- State mặc định: `~/.local/state/fxvpn/state.json` (tự tạo lần đầu)
- SOCKS5 mặc định: `127.0.0.1:1080`
- `--version` — in phiên bản

Cấu hình bằng cờ:

```bash
./fxvpn-desktop --state /duong/dan/state.json --socks 127.0.0.1:2080
```

**Dùng lại account của bản Docker:**

```bash
# Volume của container thường ở ./data/state.json cạnh docker-compose.yml
./fxvpn-desktop --state /duong/dan/data/state.json
```

Đọc được file đó là đủ (không cần ghi); desktop app ghi state riêng của nó
trừ khi bạn chỉ định.

**Biến môi trường** (thay cho cờ): `FXVPN_STATE_FILE`, `SOCKS_ADDR`,
`GUARDIAN_ENDPOINT` (chỉ đổi khi test staging).

## 6. Cài vào hệ thống (tuỳ chọn)

```bash
sudo install -m 755 fxvpn-desktop /usr/local/bin/
# hoặc chỉ cho mình:
mkdir -p ~/.local/bin && cp fxvpn-desktop ~/.local/bin/
```

Shortcut desktop (menu ứng dụng):

```bash
cat > ~/.local/share/applications/fxvpn.desktop <<'EOF'
[Desktop Entry]
Type=Application
Name=fxvpn — Firefox VPN
Exec=/usr/local/bin/fxvpn-desktop
Icon=application-x-executable
Categories=Network;
EOF
```

## 7. Dùng VPN

1. Tab **Account** → nhập email + mật khẩu Firefox → **Đăng nhập** → nhập mã
   6 số từ email nếu được hỏi (2FA)
2. Tab **Vị trí** → chọn country → city → **Kết nối**
3. Trỏ ứng dụng tới SOCKS5 `127.0.0.1:1080` (VD: Firefox → Settings → Network
   Settings → Manual proxy → SOCKS Host `127.0.0.1`, Port `1080`, bật
   "Proxy DNS when using SOCKS v5")
4. Tab **Test** → **Chạy test exit IP** để xác nhận traffic đi qua VPN

Nhiều account: thêm thoải mái — token keeper tự giữ token tất cả; **🔄
Refresh token tất cả account** chạy thủ công bất cứ lúc nào.

## 8. Tường lửa

SOCKS5 chỉ listen `127.0.0.1` — không cần mở port. Nếu đổi `--socks
0.0.0.0:1080` cho LAN:

```bash
# firewalld (Fedora/RHEL)
sudo firewall-cmd --add-port=1080/tcp --permanent && sudo firewall-cmd --reload
# ufw (Ubuntu/Debian)
sudo ufw allow 1080/tcp
```

## 9. Gỡ cài đặt

```bash
rm -f /usr/local/bin/fxvpn-desktop ~/.local/share/applications/fxvpn.desktop
rm -rf ~/.local/state/fxvpn   # xoá luôn state (account/token) nếu muốn
```

---

## Xử lý sự cố

| Hiện tượng | Nguyên nhân / cách xử lý |
|---|---|
| `pkg-config: Package xkbcommon not found` khi build | thiếu gói `-dev` — quay lại bước 2, chạy đúng khối distro |
| `fatal error: wayland-client.h: No such file` | thiếu `libwayland-dev` (Debian) / `wayland-devel` (Fedora) |
| `cannot open display` lúc chạy | chạy ngoài session đồ họa (SSH thuần, TTY). App cần Wayland/X11 — dùng `ssh -X` cho X11 forwarding |
| Cửa sổ mở nhưng **trắng/đen** | GPU thiếu Vulkan → `make cpu` rồi chạy lại |
| Chạy báo `libEGL.so.1: cannot open shared object` | thiếu runtime lib — `sudo apt-get install libegl1 libgl1 libxkbcommon0 libwayland-client0` |
| Build OK nhưng crash ngay với `vk...` trong stack | driver Vulkan hỏng — `make cpu` |
| Tab Account hiện ⚠ vàng "Fastly chặn tạm thời" | Fastly chặn IP server bằng CAPTCHA — **account vẫn hoạt động bình thường**, tự retry; không cần làm gì |
| Tab Account hiện ⛔ đỏ "token chết" | account bị sign-out/đổi mật khẩu server-side → xoá, thêm lại account đó |
| SOCKS5 đã chạy nhưng web không vào được | kiểm tra app có trúng proxy không (bước 7.3), và thử Tab Test — nếu Test OK nhưng web lỗi, proxy của trình duyệt chưa set đúng |
| Đổi location xong IP không đổi | bấm Test — edge session rebuild cần vài giây; nếu vẫn cũ, Ngắt kết nối → Kết nối lại |

## Bản dựng cho kiến trúc khác

```bash
# ARM64 (VD: build trên x86 để chạy Raspberry Pi 5 / arm server)
GOARCH=arm64 CC=aarch64-linux-gnu-gcc make GOFLAGS=""
# (cần cross toolchain: sudo apt install gcc-aarch64-linux-gnu)
```

App là binary tĩnh trừ các lib đồ họa hệ thống — copy kèm cấu hình máy đích
có đủ lib ở bước 2 là chạy.
