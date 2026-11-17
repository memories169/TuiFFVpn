package browsercapture

import (
	"strings"
	"testing"
)

func TestLoginURLSubstitutesAllPlaceholders(t *testing.T) {
	url := loginURL("309b8d5e66fb61e191a9f1013bdf8dad")
	for _, bad := range []string{"__OAUTH_CLIENT_ID__", "__OAUTH_STATE__"} {
		if strings.Contains(url, bad) {
			t.Fatalf("placeholder %s not substituted: %s", bad, url)
		}
	}
	if !strings.Contains(url, "client_id=5882386c6d801776") {
		t.Fatalf("client_id missing: %s", url)
	}
	if !strings.Contains(url, "state=309b8d5e66fb61e191a9f1013bdf8dad") {
		t.Fatalf("state missing: %s", url)
	}
	if !strings.Contains(url, "context=oauth_webchannel_v1") {
		t.Fatalf("context missing: %s", url)
	}
}

func TestLoginURLUniqueState(t *testing.T) {
	a := loginURL(randomHex(16))
	b := loginURL(randomHex(16))
	if a == b {
		t.Fatal("two runs produced identical URLs")
	}
}
