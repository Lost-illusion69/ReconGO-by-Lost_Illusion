package prober

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

const maxBodyBytes = 1 << 20 // 1 MiB

// MaxBodyBytes is exported for the pkg/prober wrapper.
const MaxBodyBytes = maxBodyBytes

var (
	titleRe = regexp.MustCompile(`(?is)<title[^>]*>\s*(.*?)\s*</title>`)
	iconRe  = regexp.MustCompile(`(?is)<link[^>]+rel=["']?(?:shortcut\s+icon|icon)["']?[^>]+href=["']([^"']+)["']`)
	iconRe2 = regexp.MustCompile(`(?is)<link[^>]+href=["']([^"']+)["'][^>]+rel=["']?(?:shortcut\s+icon|icon)["']?`)
)

// Options configures HTTP probe behaviour (traffic shaping, headers, proxy).
type Options struct {
	Timeout     time.Duration
	Delay       time.Duration
	RandomAgent bool
	Verbose     bool
	Headers     map[string]string
	ProxyURL    string
}

func (o Options) withDefaults() Options {
	if o.Timeout <= 0 {
		o.Timeout = 5 * time.Second
	}
	return o
}

// ParseHeaders parses "Key: Value, Key2: Value2" into a header map.
func ParseHeaders(raw string) (map[string]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	out := make(map[string]string)
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, val, ok := strings.Cut(part, ":")
		if !ok {
			return nil, fmt.Errorf("prober: invalid header %q (want \"Key: Value\")", part)
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		if key == "" {
			return nil, fmt.Errorf("prober: empty header name in %q", part)
		}
		out[key] = val
	}
	return out, nil
}

// ExtractTitle returns the first HTML title in body.
func ExtractTitle(body []byte) string {
	m := titleRe.FindSubmatch(body)
	if m == nil {
		return ""
	}
	return strings.Join(strings.Fields(string(m[1])), " ")
}
