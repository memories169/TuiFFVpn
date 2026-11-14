package webapp

import (
	"strconv"
	"strings"
)

// parseQuotaBytes parses a Guardian quota string ("1234567890",
// "1.5 GB", "512 MB", "1 TB", "100GB"…) into bytes. ok=false when unparseable.
func parseQuotaBytes(s string) (float64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	// Plain byte count?
	if n, err := strconv.ParseFloat(s, 64); err == nil {
		return n, true
	}
	// Humanized form: number + unit (space optional).
	fields := strings.Fields(s)
	var numStr, unit string
	if len(fields) == 2 {
		numStr, unit = fields[0], fields[1]
	} else if len(fields) == 1 {
		// Split digits from letters: "100GB" → "100", "GB".
		i := 0
		for i < len(fields[0]) && (fields[0][i] >= '0' && fields[0][i] <= '9' || fields[0][i] == '.') {
			i++
		}
		if i == 0 || i == len(fields[0]) {
			return 0, false
		}
		numStr, unit = fields[0][:i], fields[0][i:]
	} else {
		return 0, false
	}
	n, err := strconv.ParseFloat(numStr, 64)
	if err != nil {
		return 0, false
	}
	unit = strings.ToUpper(strings.TrimSpace(unit))
	unit = strings.TrimSuffix(unit, "S") // "GBS" → "GB"
	var mult float64
	switch unit {
	case "B":
		mult = 1
	case "KB", "KIB":
		mult = 1024
	case "MB", "MIB":
		mult = 1024 * 1024
	case "GB", "GIB":
		mult = 1024 * 1024 * 1024
	case "TB", "TIB":
		mult = 1024 * 1024 * 1024 * 1024
	default:
		return 0, false
	}
	return n * mult, true
}

func parseQuotaBytesSafe(s string) float64 {
	n, _ := parseQuotaBytes(s)
	return n
}
