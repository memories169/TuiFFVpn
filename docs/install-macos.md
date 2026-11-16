# Cài đặt — macOS

Engine chạy được trên macOS (Intel và Apple Silicon) qua bản web console.
GUI desktop trong repo nhắm Linux; Gio có backend macOS nên port sau có thể
làm trực tiếp từ `webui/desktop`.

## Cách 1 — Homebrew Go, chạy console native

```bash
brew install go git
git clone https://github.com/memories169/TuiFFVpn.git && cd TuiFFVpn
CGO_ENABLED=0 go build -o fxvpn-webui ./webui/cmd/fxvpn-webui
./fxvpn-webui -http :9090 -socks 127.0.0.1:1080 -state ~/Library/Application\ Support/fxvpn/state.json
```

Mở `http://localhost:9090`.

## Cách 2 — Docker

Docker Desktop cho Mac chạy image như [install-docker.md](install-docker.md).

## SOCKS5 cho app macOS

System Settings → Network → chi tiết kết nối → Proxies → SOCKS proxy:
`127.0.0.1:1080`. Hoặc chỉ đặt cho từng app (Firefox riêng là đủ — hệ thống
proxy sẽ bắt cả traffic Apple).

## Ghi chú

- macOS 13+ dùng ~6h token Mozilla như mọi nền tảng; rotator/keeper chạy
  trong console tự gia hạn.
- Sau khi Mac ngủ, tunnel MASQUE tự dựng lại ở lần request tiếp theo; nếu
  không, bấm "Kết nối lại" trong tab Trạng thái.
