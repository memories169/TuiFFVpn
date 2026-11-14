package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Old single-account state files must migrate to the Accounts list on load.
func TestLegacyMigration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	legacy := map[string]any{
		"admin": map[string]any{"user": "admin", "pass_salt": "s", "pass_hash": "h", "theme": "light"},
		"tokens": map[string]any{
			"access_token": "old-at", "refresh_token": "old-rt",
			"expires_in": 3600, "email": "old@gmail.com",
			"obtained_at": time.Now().Format(time.RFC3339),
		},
	}
	data, _ := json.Marshal(legacy)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	st, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	ac := st.ActiveAccount()
	if ac == nil {
		t.Fatal("no active account after migration")
	}
	if ac.Email != "old@gmail.com" || ac.AccessToken != "old-at" || ac.RefreshToken != "old-rt" {
		t.Fatalf("migrated account wrong: %+v", ac)
	}
	if st.Active != "old@gmail.com" {
		t.Fatalf("active = %q", st.Active)
	}
}

func TestUpsertAndSwitch(t *testing.T) {
	s := &Store{}
	s.UpsertAccount("a@x.com", "at-a", "rt-a", 3600)
	s.UpsertAccount("b@x.com", "at-b", "rt-b", 3600)
	if s.Active != "b@x.com" {
		t.Fatalf("active = %q, want last added", s.Active)
	}
	if !s.SetActive("a@x.com") {
		t.Fatal("SetActive failed")
	}
	ac := s.ActiveAccount()
	if ac.Email != "a@x.com" {
		t.Fatalf("active = %q", ac.Email)
	}
	// Re-adding the same email updates it, keeps one slot.
	s.UpsertAccount("a@x.com", "at-a2", "", 60)
	if len(s.Accounts) != 2 {
		t.Fatalf("accounts = %d, want 2", len(s.Accounts))
	}
	if s.ActiveAccount().AccessToken != "at-a2" {
		t.Fatalf("token not updated")
	}
	// Removing the active one falls back to the other.
	if !s.RemoveAccount("a@x.com") {
		t.Fatal("RemoveAccount failed")
	}
	if s.Active != "b@x.com" {
		t.Fatalf("after remove active = %q", s.Active)
	}
}

func TestAccessTokenValid(t *testing.T) {
	ac := &Account{AccessToken: "x", ExpiresIn: 3600, ObtainedAt: time.Now()}
	if !ac.AccessTokenValid(time.Now()) {
		t.Fatal("fresh token should be valid")
	}
	ac.ObtainedAt = time.Now().Add(-2 * time.Hour)
	if ac.AccessTokenValid(time.Now()) {
		t.Fatal("expired token should be invalid")
	}
}
