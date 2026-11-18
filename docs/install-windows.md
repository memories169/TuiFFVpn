# Cài đặt trên Windows

App desktop native **fxvpn** chạy trực tiếp trên Windows 10/11 — dùng cùng
engine Go với bản Linux (token keeper, rotator, MASQUE, SOCKS5), không cần
Docker, không cần màn hình đăng nhập admin.

## Cách 1 — Tải bản dựng sẵn (khuyên dùng)

Mỗi push lên `main` và mỗi tag `v*` được GitHub Actions build tại
[Releases](https://github.com/memories169/TuiFFVpn/releases) (tab
**Actions → build-desktop** cho bản main):

```powershell
# Tải fxvpn-desktop-windows-amd64.exe, đổi tên cho gọn rồi chạy:
Invoke-WebRequest <link-từ-Releases> -OutFile fxvpn.exe
.\fxvpn.exe
```

Windows có thể hiện SmartScreen lần đầu — bấm **More info → Run anyway**
(binary chưa ký số).

## Cách 2 — Build từ nguồn

### Điều kiện

- **Go ≥ 1.21** — [go.dev/dl](https://go.dev/dl/) (MSI, mặc định `C:\Program Files\Go`)
- **Git** — [git-scm.com](https://git-scm.com/download/win)
- Không cần cgo, không cần MinGW, không cần trình biên dịch C — backend
  Direct3D/GDI của Gio thuần Go.

### Build

```powershell
git clone https://github.com/memories169/TuiFFVpn.git
cd TuiFFVpn
go build -tags nometal -o fxvpn-desktop.exe .\webui\desktop\cmd\fxvpn-desktop
.\fxvpn-desktop.exe
```

(`nometal` tắt backend Metal — chỉ dành cho macOS; Windows dùng backend
win32 thuần Go.)

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
- Cấu hình lưu tại `state.json` **ngay cạnh `fxvpn-desktop.exe`** (layout
  portable: chuyển thư mục hay copy sang máy khác là dữ liệu theo theo)

## Dùng chung account với bản Docker

State file giống hệt schema của container. Copy `state.json` của container
vào thư mục của exe (hoặc chạy
`fxvpn-desktop.exe --state C:\đường\dẫn\state.json`) để dùng lại toàn bộ
account có sẵn.

## Gỡ cài đặt

Xoá thư mục chứa `fxvpn-desktop.exe` (exe + `state.json`) — không có gì
khác bị cài vào hệ thống.
