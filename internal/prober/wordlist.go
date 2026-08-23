package prober

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const defaultWordlistRel = "bugbounty/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt"

// DefaultWordlistPath returns the built-in SecLists directory wordlist location
// under the user's home directory.
func DefaultWordlistPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = os.Getenv("HOME")
	}
	if home == "" {
		home = os.Getenv("USERPROFILE")
	}
	return filepath.Join(home, filepath.FromSlash(defaultWordlistRel))
}

// LoadWordlist reads a directory/file wordlist, skipping blanks and # comments.
// Each surviving entry is normalized to a rooted path (e.g. /admin).
func LoadWordlist(path string) ([]string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("prober: empty wordlist path")
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("prober: open wordlist %s: %w", path, err)
	}
	defer f.Close()

	seen := make(map[string]struct{})
	out := make([]string, 0, 4096)

	sc := bufio.NewScanner(f)
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 1024*1024)

	for sc.Scan() {
		p := NormalizeWordlistEntry(sc.Text())
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("prober: read wordlist %s: %w", path, err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("prober: wordlist %s contained no usable paths", path)
	}
	return out, nil
}

// NormalizeWordlistEntry converts a raw wordlist line into a rooted URL path.
// Empty lines, comments, URLs, and parent-directory traversals are rejected.
func NormalizeWordlistEntry(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" || strings.HasPrefix(s, "#") {
		return ""
	}
	s = strings.ReplaceAll(s, `\`, "/")
	if strings.Contains(s, "://") {
		return ""
	}
	// Strip query/fragment noise that some lists include.
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	if s == "" || s == "/" || s == "." {
		return ""
	}
	for _, part := range strings.Split(s, "/") {
		if part == ".." {
			return ""
		}
	}
	s = strings.TrimLeft(s, "/")
	if s == "" {
		return ""
	}
	if len(s) > 250 {
		return ""
	}
	return "/" + s
}
