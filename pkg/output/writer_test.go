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
		Endpoints:     []string{"/api/v1/health"},
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
	asset, ok := m["asset"].(map[string]any)
	if !ok {
		t.Fatalf("missing asset block: %v", m)
	}
	if asset["host"] != "api.example.com" {
		t.Errorf("host = %v", asset["host"])
	}
	httpBlock, ok := m["http"].(map[string]any)
	if !ok {
		t.Fatalf("missing http block: %v", m)
	}
	if httpBlock["status_code"].(float64) != 200 {
		t.Errorf("status_code = %v", httpBlock["status_code"])
	}
	eps, ok := m["endpoints"].([]any)
	if !ok || len(eps) != 1 {
		t.Errorf("endpoints = %v", m["endpoints"])
	}
}

func TestWriteJSONEmptyEndpoints(t *testing.T) {
	var buf bytes.Buffer
	wr := NewWriter(FormatJSON, &buf)
	a := sampleAsset()
	a.Endpoints = nil
	if err := wr.Write(a); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	eps, ok := m["endpoints"].([]any)
	if !ok {
		t.Fatalf("endpoints key missing: %v", m)
	}
	if len(eps) != 0 {
		t.Errorf("expected empty endpoints array, got %v", eps)
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
	if !strings.HasPrefix(lines[0], "Host,IPs,URL,StatusCode") {
		t.Errorf("unexpected header: %s", lines[0])
	}
	if !strings.Contains(lines[1], "api.example.com") {
		t.Errorf("row missing host: %s", lines[1])
	}
}

func TestWriteText(t *testing.T) {
	var buf bytes.Buffer
	wr := NewWriter(FormatText, &buf)
	if err := wr.Write(sampleAsset()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := wr.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "api.example.com") {
		t.Errorf("missing host: %s", out)
	}
	if !strings.Contains(out, "[200 OK]") {
		t.Errorf("missing status badge: %s", out)
	}
	if !strings.Contains(out, "/api/v1/health") {
		t.Errorf("missing endpoint: %s", out)
	}
	if !strings.Contains(out, "SCAN SUMMARY") {
		t.Errorf("missing summary footer: %s", out)
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
