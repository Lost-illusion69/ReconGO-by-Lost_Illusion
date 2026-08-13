package mmh3

import "encoding/base64"

// EncodeBytesRFC2045 base64-encodes data with a newline every 76 characters
// and a trailing newline, matching Python base64.encodebytes (Shodan favicon).
func EncodeBytesRFC2045(data []byte) string {
	if len(data) == 0 {
		return "\n"
	}

	encoded := base64.StdEncoding.EncodeToString(data)
	var out []byte
	out = append(out, encoded...)

	// Insert newlines every 76 chars (in-place rebuild).
	wrapped := make([]byte, 0, len(out)+len(out)/76+1)
	for i := 0; i < len(out); i += 76 {
		end := i + 76
		if end > len(out) {
			end = len(out)
		}
		wrapped = append(wrapped, out[i:end]...)
		if end < len(out) {
			wrapped = append(wrapped, '\n')
		}
	}
	wrapped = append(wrapped, '\n')
	return string(wrapped)
}

// FaviconHash returns the Shodan-compatible MMH3 hash of favicon bytes.
func FaviconHash(favicon []byte) int32 {
	return HashString(EncodeBytesRFC2045(favicon))
}
