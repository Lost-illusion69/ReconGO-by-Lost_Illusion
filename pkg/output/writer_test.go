package output

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Lost-illusion69/recongo/pkg/prober"
)

func sampleAsset() prober.AssetResult {
	return prober.AssetResult{
		Host:          "api.example.com",
		IPs:           []string{"1.2.3.4", "5.6.7.8"},
		URL:           "https://api.example.com",
		StatusCode:    200,
		Title:         "API Portal",
		Server:        "nginx",
		ContentLength: 128,
		ResponseTime:  42 * time.Millisecond,
	}
}

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	wr := NewWriter(FormatJSON, &buf)
	if err := wr.Write(sampleAsset()); err != nil {
		t.Fatalf("Write: %v", err)
	}

	line := strings.TrimSpace(buf.String())
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("invalid jsonl: %v\n%s", err, line)
	}
	if m["host"] != "api.example.com" {
		t.Errorf("host = %v", m["host"])
	}
	if m["status_code"].(float64) != 200 {
		t.Errorf("status_code = %v", m["status_code"])
	}
	if m["title"] != "API Portal" {
		t.Errorf("title = %v", m["title"])
	}
}

func TestWriteCSV(t *testing.T) {
	var buf bytes.Buffer
	wr := NewWriter(FormatCSV, &buf)
	if err := wr.Write(sampleAsset()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := wr.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected header + 1 row, got %d lines:\n%s", len(lines), buf.String())
	}
	if !strings.HasPrefix(lines[0], "Host,IPs,URL,StatusCode,Title,Server,ContentLength") {
		t.Errorf("unexpected header: %s", lines[0])
	}
	if !strings.Contains(lines[1], "api.example.com") {
		t.Errorf("row missing host: %s", lines[1])
	}
	if !strings.Contains(lines[1], "1.2.3.4;5.6.7.8") {
		t.Errorf("row missing joined IPs: %s", lines[1])
	}
}

func TestWriteText(t *testing.T) {
	var buf bytes.Buffer
	wr := NewWriter(FormatText, &buf)
	if err := wr.Write(sampleAsset()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "[HTTP]") {
		t.Errorf("missing [HTTP] marker: %s", out)
	}
	if !strings.Contains(out, "https://api.example.com") {
		t.Errorf("missing URL: %s", out)
	}
	if !strings.Contains(out, `title="API Portal"`) {
		t.Errorf("missing title: %s", out)
	}
}

func TestWriterRunConcurrentSafe(t *testing.T) {
	var buf bytes.Buffer
	wr := NewWriter(FormatJSON, &buf)

	ch := make(chan prober.AssetResult, 8)
	errCh := wr.Run(context.Background(), ch)

	for i := 0; i < 8; i++ {
		a := sampleAsset()
		a.Host = "host" + string(rune('a'+i)) + ".example.com"
		ch <- a
	}
	close(ch)

	if err := <-errCh; err != nil {
		t.Fatalf("Run: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 8 {
		t.Fatalf("expected 8 json lines, got %d", len(lines))
	}
}

func TestParseFormat(t *testing.T) {
	cases := map[string]Format{
		"text":  FormatText,
		"json":  FormatJSON,
		"jsonl": FormatJSON,
		"csv":   FormatCSV,
		"TEXT":  FormatText,
		"":      FormatText,
	}
	for in, want := range cases {
		got, err := ParseFormat(in)
		if err != nil {
			t.Errorf("ParseFormat(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseFormat(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := ParseFormat("xml"); err == nil {
		t.Error("ParseFormat(xml) expected error")
	}
}
