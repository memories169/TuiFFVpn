# fxvpn-desktop build.
#
# On a real Linux machine (Wayland or X11) with the dev headers installed —
# see docs/desktop-linux.md — plain `make` builds the full GUI:
#   make            # native build with Wayland + X11 + Vulkan/GPU rendering
#   make cpu        # native build without Vulkan (falls back to GL/CPU render)
#
# Inside a container WITHOUT the dev libs (CI, this workspace) use:
#   make headless   # compile-check only — binary has NO window system linked

GO ?= go
BIN := fxvpn-desktop
PKG := ./webui/desktop/cmd/fxvpn-desktop
VERSION ?= $(shell date -u +%Y%m%d)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all native cpu headless test vet fmt clean

all: native

native:
	$(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN) $(PKG)

cpu:
	$(GO) build -trimpath -tags novulkan -ldflags="$(LDFLAGS)" -o $(BIN) $(PKG)

# Container compile check: no window system is linked (build tags disable
# Wayland/X11/Vulkan). The binary cannot open a window — it only proves the
# code compiles. Real builds happen on the user machine via `make`.
headless:
	$(GO) build -trimpath -tags nowayland,nox11,novulkan -ldflags="$(LDFLAGS)" -o /dev/null $(PKG)

test:
	$(GO) test -tags nowayland,nox11,novulkan ./...

vet:
	$(GO) vet -tags nowayland,nox11,novulkan ./webui/...

fmt:
	gofmt -l webui/ && test -z "$$(gofmt -l webui/)"

clean:
	rm -f $(BIN)
