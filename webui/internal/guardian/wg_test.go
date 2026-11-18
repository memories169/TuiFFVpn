package guardian

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRegisterDeviceAgainstMockGuardian drives RegisterDevice through a
// mock Guardian: 201 shape {"device": {...}} and the bare-device shape both
// parse; auth errors map to ErrTokenInvalid.
func TestRegisterDeviceAgainstMockGuardian(t *testing.T) {
	deviceJSON := map[string]any{
		"name":         "test",
		"unique_id":    "uid-1",
		"pubkey":       "pub",
		"created_at":   "2026-11-18T00:00:00Z",
		"ipv4_address": "10.5.0.2",
		"ipv6_address": "fd00::2",
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/vpn/device" && r.Method == http.MethodPost:
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("bad body: %v", err)
			}
			if body["pubkey"] != "testpub" || body["name"] != "testdev" {
				t.Errorf("unexpected body: %v", body)
			}
			if r.Header.Get("Authorization") != "Bearer token-ok" {
				t.Errorf("bad auth header: %q", r.Header.Get("Authorization"))
			}
			wrapped := map[string]any{"device": deviceJSON}
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(wrapped)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := &Client{Endpoint: srv.URL, Token: "token-ok"}
	dev, err := c.RegisterDevice(context.Background(), "testdev", "uid-1", "testpub")
	if err != nil {
		t.Fatal(err)
	}
	if dev.IPv4 != "10.5.0.2" || dev.IPv6 != "fd00::2" {
		t.Fatalf("device IPs: %+v", dev)
	}

	// Bare (unwrapped) shape:
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(deviceJSON)
	}))
	defer srv2.Close()
	c2 := &Client{Endpoint: srv2.URL, Token: "token-ok"}
	dev2, err := c2.RegisterDevice(context.Background(), "testdev", "uid-1", "testpub")
	if err != nil {
		t.Fatal(err)
	}
	if dev2.IPv4 != "10.5.0.2" {
		t.Fatalf("bare device parse: %+v", dev2)
	}

	// 401 → ErrTokenInvalid:
	srv3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"code":401,"errno":120,"error":"jwt malformed"}`))
	}))
	defer srv3.Close()
	c3 := &Client{Endpoint: srv3.URL, Token: "bad"}
	_, err = c3.RegisterDevice(context.Background(), "n", "u", "p")
	if err == nil {
		t.Fatal("expected 401 error")
	}
	if !isTokenInvalidErr(err) {
		t.Fatalf("expected ErrTokenInvalid, got: %v", err)
	}
}

func isTokenInvalidErr(err error) bool {
	if err == nil {
		return false
	}
	type unwrapper interface{ Unwrap() error }
	for e := error(err); e != nil; {
		if e == ErrTokenInvalid {
			return true
		}
		u, ok := e.(unwrapper)
		if !ok {
			return false
		}
		e = u.Unwrap()
	}
	return false
}

// TestFetchWGServersParsesGuardianShape uses the exact response layout the
// official client's ServerCountryModel consumes.
func TestFetchWGServersParsesGuardianShape(t *testing.T) {
	payload := map[string]any{
		"countries": []map[string]any{
			{
				"name": "Netherlands",
				"code": "NL",
				"cities": []map[string]any{
					{
						"name": "Amsterdam",
						"code": "AMS",
						"servers": []map[string]any{
							{
								"hostname":       "nl107-wg.ams1.mozgcp.net",
								"ipv4_addr_in":   "185.199.108.153",
								"ipv4_gateway":   "10.64.0.1",
								"public_key":     "WGKEY1",
								"port":           53,
								"weight":         64,
							},
						},
					},
				},
			},
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/vpn/servers" {
			json.NewEncoder(w).Encode(payload)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := &Client{Endpoint: srv.URL, Token: "token-ok"}
	raw, err := c.FetchWGServers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Countries []struct {
			Cities []struct {
				Servers []struct {
					PublicKey string `json:"public_key"`
				} `json:"servers"`
			} `json:"cities"`
		} `json:"countries"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Countries) != 1 || len(out.Countries[0].Cities[0].Servers) != 1 {
		t.Fatalf("unexpected shape: %s", raw)
	}
	if out.Countries[0].Cities[0].Servers[0].PublicKey != "WGKEY1" {
		t.Fatalf("public key lost: %s", raw)
	}
}
