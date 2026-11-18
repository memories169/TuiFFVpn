# Cài đặt trên macOS

App desktop native **fxvpn** chạy trực tiếp trên macOS 12+ (Intel và Apple
Silicon) — dùng cùng engine Go với bản Linux (token keeper, rotator,
MASQUE, SOCKS5), không cần Docker, không cần màn hình đăng nhập admin.

## Cách 1 — Tải bản dựng sẵn (khuyên dùng)

Mỗi push lên `main` và mỗi tag `v*` được GitHub Actions build tại
[Releases](https://github.com/memories169/TuiFFVpn/releases) (tab
**Actions → build-desktop** cho bản main):

```bash
# Intel:
curl -LO <link fxvpn-desktop-macos-amd64-từ-Releases>
mv fxvpn-desktop-macos-amd64 fxvpn && chmod +x fxvpn

# Apple Silicon (M1/M2/M3/M4):
curl -LO <link fxvpn-desktop-macos-arm64-từ-Releases>
mv fxvpn-desktop-macos-arm64 fxvpn && chmod +x fxvpn

./fxvpn
```

Lần chạy đầu macOS có thể chặn vì binary chưa ký/notarize: **System
Settings → Privacy & Security → nút "Open Anyway"** (hoặc
`xattr -d com.apple.quarantine fxvpn`).

## Cách 2 — Build từ nguồn

### Điều kiện

- **Go ≥ 1.21** — `brew install go` hoặc [go.dev/dl](https://go.dev/dl/)
- **Xcode Command Line Tools** — `xcode-select --install` (backend Metal
  của Gio là cgo với framework hệ thống — bắt buộc trên macOS)
- **Chrome/Chromium/Edge/Brave/Helium** để dùng đăng nhập qua trình duyệt
  (không bắt buộc — có thể dán token thủ công)

### Build

```bash
git clone https://github.com/memories169/TuiFFVpn.git
cd TuiFFVpn
go build -o fxvpn-desktop ./webui/desktop/cmd/fxvpn-desktop
./fxvpn-desktop
```

## Chạy

- Cửa sổ app mở ra với 4 tab: **Trạng thái / Account / Vị trí / Test**
- Đăng nhập account: 2 cách —
  1. Nhập **email + mật khẩu** (+ mã 2FA nếu có) rồi bấm **Đăng nhập**
  2. Nếu Fastly chặn (lỗi 406/CAPTCHA): dùng userscript
     `scripts/fxvpn-desktop-grabber.user.js` trong Firefox thật của bạn —
     script tự ĐỔI OAuth ngay trong browser rồi copy access/refresh vào
     clipboard; dán vào form "Thêm bằng token" (email + access +
     refresh). Chỉ request từ browser thật mới qua được edge khi IP bị
     CAPTCHA-lock.

     Cách tốt hơn: dán **ingest key** (tab Logs của app, banner
     "Ingest key (userscript)") vào `INGEST_KEY` ở đầu userscript — một
     lần duy nhất, vì key được lưu vĩnh viễn trong `state.json` và KHÔNG
     ĐỔI sau khi khởi động lại app. Sau đó userscript tự đẩy cả bộ
     email + access + refresh + proxy pass vào app, không cần dán tay.
- SOCKS5 proxy lắng nghe `127.0.0.1:1080` (đổi bằng `--socks 127.0.0.1:9999`)
- Cấu hình lưu tại `~/Library/Application Support/fxvpn/state.json`

## Dùng chung account với bản Docker

State file giống hệt schema của container. Copy `state.json` của container
vào `~/Library/Application Support/fxvpn/state.json` (hoặc chạy
`./fxvpn-desktop --state /đường/dẫn/state.json`) để dùng lại toàn bộ
account có sẵn.

## Gỡ cài đặt

Xoá binary và thư mục `~/Library/Application Support/fxvpn/` — app không
cài gì khác vào hệ thống.
