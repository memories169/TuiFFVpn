# Cài đặt — Windows (WSL2 hoặc web console)

Engine MASQUE/SOCKS5 chạy tốt trên Windows qua **WSL2**; GUI native desktop
hiện chỉ build cho Linux (Gio hỗ trợ Windows — port có thể làm sau, xem
`webui/desktop` — nhưng phần đóng gói trong repo này nhắm Linux trước).

## Cách 1 — Web console trong WSL2 (khuyên dùng)

1. Cài [WSL2](https://learn.microsoft.com/vi-vn/windows/wsl/install):
   ```powershell
   wsl --install -d Debian
   ```
2. Trong WSL: cài Go ≥ 1.21 + git, clone repo, build bản console (không cần
   thư viện GUI):
   ```bash
   sudo apt-get update && sudo apt-get install -y golang-go git
   git clone https://github.com/memories169/TuiFFVpn.git && cd TuiFFVpn
   CGO_ENABLED=0 go build -o fxvpn-webui ./webui/cmd/fxvpn-webui
   ./fxvpn-webui -http :9090 -socks 127.0.0.1:1080 -state ~/fxvpn-state.json
   ```
3. Trên Windows: mở `http://localhost:9090` — console đầy đủ tính năng.
4. Trỏ app Windows (Firefox, v.v.) tới SOCKS5 `127.0.0.1:1080` (WSL2 tự
   forward localhost).

## Cách 2 — Docker Desktop

Cài Docker Desktop cho Windows, sau đó làm đúng phần
[install-docker.md](install-docker.md) trong PowerShell.

## Ghi chú

- Tường lửa Windows có thể hỏi lần đầu khi SOCKS5 listen ngoài localhost —
  chọn "Chỉ mạng riêng".
- Fastly CAPTCHA (⚠ trong console) là chặn IP: đổi IP VPS/network hoặc chờ —
  không phải lỗi account.
