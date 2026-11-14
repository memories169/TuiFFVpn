package guardian

import "encoding/base64"

func base64url(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}
