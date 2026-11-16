# syntax=docker/dockerfile:1
# Build stage.
# Go 1.22: the shared go.mod declares go 1.21 (the desktop GUI's Gio needs
# it). The container binaries themselves never import the GUI package, so
# Gio is downloaded but never compiled — CGO stays off and the image ships
# no GUI libraries.
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY webui/ ./webui/
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/fxvpn-webui ./webui/cmd/fxvpn-webui \
    && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/fxvpn-token ./webui/cmd/fxvpn-token

# Runtime stage. The web console and userspace SOCKS5 proxy need no root; the
# token capture runs in the browser on the user's PC (userscript) so the image
# ships no browser stack.
FROM alpine:3.20
RUN apk add --no-cache ca-certificates su-exec tzdata \
    && adduser -D -u 10001 fxvpn \
    && mkdir -p /data \
    && chown 10001:10001 /data

WORKDIR /app
COPY --from=build /out/fxvpn-webui /app/fxvpn-webui
COPY --from=build /out/fxvpn-token /app/fxvpn-token
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Web UI + SOCKS5 proxy
EXPOSE 9090 1080
# State (tokens + selected server) is written here; bind a volume to persist.
VOLUME /data
# entrypoint runs as root, prepares /data, then drops to the fxvpn user
# (uid 10001).
ENTRYPOINT ["/app/entrypoint.sh"]
