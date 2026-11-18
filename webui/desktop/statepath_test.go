package desktop

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDefaultStatePathNextToBinary pins the portable state layout: the
// default state file must resolve next to the running executable, not in a
// per-user config/state directory.
func TestDefaultStatePathNextToBinary(t *testing.T) {
	if os.Getenv("FXVPN_STATE_FILE") != "" {
		t.Skip("FXVPN_STATE_FILE overrides the default path")
	}
	t.Setenv("FXVPN_STATE_FILE", "")

	got := DefaultStatePath()
	if filepath.Base(got) != "state.json" {
		t.Fatalf("state file name = %q, want state.json", got)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("os.Executable unavailable: %v", err)
	}
	wantDir := filepath.Dir(exe)
	if filepath.Dir(got) != wantDir {
		t.Fatalf("state dir = %q, want the binary dir %q", filepath.Dir(got), wantDir)
	}
}

// TestDefaultStatePathOverride checks the escape hatch still wins.
func TestDefaultStatePathOverride(t *testing.T) {
	t.Setenv("FXVPN_STATE_FILE", "/tmp/explicit/state.json")
	if got := DefaultStatePath(); got != "/tmp/explicit/state.json" {
		t.Fatalf("override ignored: got %q", got)
	}
}
