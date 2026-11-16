# Cài đặt — Docker image (fxvpn-webui console)

Repo: [github.com/memories169/TuiFFVpn](https://github.com/memories169/TuiFFVpn)

Bản container là **web console + SOCKS5 proxy** đặt trên server/NAS. Native
desktop app là một sản phẩm riêng chạy trên PC — hai bên dùng chung schema
state file (trỏ `--state` của desktop app vào volume của container nếu muốn
dùng lại account).

## Tải source

```bash
git clone https://github.com/memories169/TuiFFVpn.git
cd TuiFFVpn
```

## Build image

```bash
docker build -t fxvpn .
# hoặc dùng image prebuilt từ GHCR:
docker pull ghcr.io/memories169/tuiffvpn:latest
```

## docker-compose

Xem `docker-compose.yml` trong repo — bộ tham số tối thiểu:

```yaml
services:
  fxvpn:
    build: .
    ports:
      - "9090:9090"          # web console
    environment:
      SOCKS_ADDR: "127.0.0.1:1080"   # SOCKS5 trong container (map nếu cần)
      # FXVPN_ROTATE_INTERVAL: 30m    # xoay account
      # FXVPN_KEEPER_INTERVAL: 24h    # keeper giữ token mọi account
      # FXVPN_KEEPER_WORKERS: 4
      # FXVPN_INGEST_KEY: <secret>    # userscript/PC ingest + edge API
    volumes:
      - ./data:/data
    restart: unless-stopped
```

Mở console: `http://<host>:9090` — đăng nhập admin mặc định `admin`/`admin`
(đổi ngay trong tab Quản trị).

## SOCKS5 ra ngoài LAN

Mặc định proxy chỉ listen trong container. Muốn LAN dùng:

```yaml
    environment:
      SOCKS_ADDR: "0.0.0.0:1080"
    ports:
      - "9090:9090"
      - "1080:1080"
```

## Cập nhật

```bash
git pull && docker compose up -d --build
```

State (`/data/state.json`) giữ nguyên giữa các lần build — account, token,
location chọn đều được bảo lưu.
