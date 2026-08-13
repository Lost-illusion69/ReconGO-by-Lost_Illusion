package mmh3

import (
	"strings"
	"testing"
)

func TestHashKnownVectors(t *testing.T) {
	cases := []struct {
		input string
		want  int32
	}{
		{"", 0},
		{"hello", 613153351},
		{"ReconGo", -580840698},
	}

	for _, tc := range cases {
		got := HashString(tc.input)
		if got != tc.want {
			t.Errorf("HashString(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}
}

func TestEncodeBytesRFC2045(t *testing.T) {
	data := []byte("hello")
	enc := EncodeBytesRFC2045(data)
	// Python base64.encodebytes always ends with a trailing newline.
	if enc[len(enc)-1] != '\n' {
		t.Fatal("expected trailing newline")
	}

	empty := EncodeBytesRFC2045(nil)
	if empty != "\n" {
		t.Errorf("empty encode = %q, want newline", empty)
	}

	// Cross-check against Python-style wrapping for a longer payload.
	long := make([]byte, 76)
	for i := range long {
		long[i] = 'A'
	}
	encLong := EncodeBytesRFC2045(long)
	if !strings.Contains(encLong, "\n") {
		t.Error("expected wrapped newlines for long payload")
	}
}

func TestFaviconHashDeterministic(t *testing.T) {
	icon := []byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a}
	h1 := FaviconHash(icon)
	h2 := FaviconHash(icon)
	if h1 != h2 {
		t.Fatalf("FaviconHash not deterministic: %d vs %d", h1, h2)
	}
}
