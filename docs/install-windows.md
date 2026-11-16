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
- Đăng nhập account: bấm **🌐 Đăng nhập qua trình duyệt** — app tự mở
  Chrome/Edge/Brave/Helium cài sẵn trên máy, bạn đăng nhập Firefox account
  trong đó, token được bắt tự động (không cần userscript). Không có trình
  duyệt nào? Dán token thủ công vào khung dưới cùng.
- SOCKS5 proxy lắng nghe `127.0.0.1:1080` (đổi bằng `--socks 127.0.0.1:9999`)
- Cấu hình lưu tại `%AppData%\fxvpn\state.json`

## Dùng chung account với bản Docker

State file giống hệt schema của container. Copy `state.json` của container
vào `%AppData%\fxvpn\state.json` (hoặc chạy
`fxvpn-desktop.exe --state C:\đường\dẫn\state.json`) để dùng lại toàn bộ
account có sẵn.

## Gỡ cài đặt

Xoá `fxvpn-desktop.exe` và thư mục `%AppData%\fxvpn\` — không có gì khác
bị cài vào hệ thống.
