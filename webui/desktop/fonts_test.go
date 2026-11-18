package desktop

import (
	"strings"
	"testing"

	"gioui.org/text"
)

// TestGoFontVietnameseCoverage shapes Vietnamese strings with the embedded
// gofont collection and fails when the shaper produces glyph-less output.
func TestVietnameseCoverage(t *testing.T) {
	sh := newShaper()
	samples := []string{
		"Trạng thái",
		"Vị trí",
		"Tài khoản",
		"Đã copy ingest key — dán vào INGEST_KEY",
		"Khởi động lại",
		"không đổi sau khi khởi động lại",
		"Ấn để kết nối máy chủ gần nhất",
		"ạ ả ẫ ệ ế ỉ ọ ộ ụ ứ ữ ự",
		"Đ/th: Hà Nội — 12:34",
	}
	for _, s := range samples {
		sh.LayoutString(text.Parameters{PxPerEm: 32, MinWidth: 200, MaxWidth: 400}, s)
		glyphs := 0
		for g, ok := sh.NextGlyph(); ok; g, ok = sh.NextGlyph() {
			_ = g
			glyphs++
		}
		if glyphs == 0 && strings.TrimSpace(s) != "" {
			t.Errorf("no glyphs for %q — Vietnamese text would render blank", s)
		}
		t.Logf("%2d glyphs for %q", glyphs, s)
	}
}
