package webapp

import "testing"

func TestParseQuotaBytes(t *testing.T) {
	cases := []struct {
		in   string
		want float64
		ok   bool
	}{
		{"1234567890", 1234567890, true},
		{"1 GB", 1024 * 1024 * 1024, true},
		{"1.5 GB", 1.5 * 1024 * 1024 * 1024, true},
		{"512 MB", 512 * 1024 * 1024, true},
		{"2 TB", 2 * 1024 * 1024 * 1024 * 1024, true},
		{"100GB", 100 * 1024 * 1024 * 1024, true},
		{"1 GBS", 1024 * 1024 * 1024, true},
		{"", 0, false},
		{"abc", 0, false},
		{"1 lightyear", 0, false},
	}
	for _, c := range cases {
		got, ok := parseQuotaBytes(c.in)
		if ok != c.ok {
			t.Errorf("parseQuotaBytes(%q) ok=%v, want %v", c.in, ok, c.ok)
			continue
		}
		if ok && got != c.want {
			t.Errorf("parseQuotaBytes(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
