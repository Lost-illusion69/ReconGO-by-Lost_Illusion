// Package output provides concurrent-safe exporters for probed assets.
//
// Supported formats:
//   - text  — coloured / structured console lines
//   - json  — JSON Lines (one AssetResult per line)
//   - csv   — RFC-4180 CSV with a header row
//
// All writes are serialised through a single dedicated goroutine so callers
// never contend on the underlying file or stdout handle.
package output

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Lost-illusion69/recongo/pkg/prober"
)

// Format identifies a supported export encoding.
type Format string

const (
	FormatText Format = "text"
	FormatJSON Format = "json"
	FormatCSV  Format = "csv"
)

// ParseFormat validates and normalises a format string from the CLI.
func ParseFormat(s string) (Format, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "text", "txt", "plain", "":
		return FormatText, nil
	case "json", "jsonl", "ndjson":
		return FormatJSON, nil
	case "csv":
		return FormatCSV, nil
	default:
		return "", fmt.Errorf("output: unsupported format %q (want text|json|csv)", s)
	}
}

// ANSI colour codes used by the text formatter.  Disabled automatically when
// the destination is not a terminal (or when NO_COLOR is set).
const (
	colorReset  = "\033[0m"
	colorGreen  = "\033[32m"
	colorCyan   = "\033[36m"
	colorYellow = "\033[33m"
	colorDim    = "\033[2m"
)

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

// Writer serialises AssetResult values to an io.Writer in the chosen format.
type Writer struct {
	format Format
	w      io.Writer
	color  bool

	mu     sync.Mutex // protects csv header + concurrent Write calls
	csvHdr bool
	csvW   *csv.Writer
}

// NewWriter constructs a Writer that encodes into w using format.
// When w is an *os.File connected to a TTY and NO_COLOR is unset, text
// output includes ANSI colours.
func NewWriter(format Format, w io.Writer) *Writer {
	wr := &Writer{
		format: format,
		w:      w,
		color:  wantColor(w),
	}
	if format == FormatCSV {
		wr.csvW = csv.NewWriter(w)
	}
	return wr
}

// OpenFile creates (or truncates) path and returns a Writer bound to it,
// plus a closer the caller must invoke when finished.
func OpenFile(format Format, path string) (*Writer, func() error, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, fmt.Errorf("output: create %s: %w", path, err)
	}
	return NewWriter(format, f), f.Close, nil
}

// Write encodes a single AssetResult.  Safe for concurrent use; prefer Run
// for pipeline integration so all writes share one goroutine.
func (wr *Writer) Write(a prober.AssetResult) error {
	wr.mu.Lock()
	defer wr.mu.Unlock()

	switch wr.format {
	case FormatJSON:
		return wr.writeJSON(a)
	case FormatCSV:
		return wr.writeCSV(a)
	default:
		return wr.writeText(a)
	}
}

// Flush ensures any buffered CSV data reaches the underlying writer.
func (wr *Writer) Flush() error {
	wr.mu.Lock()
	defer wr.mu.Unlock()
	if wr.csvW != nil {
		wr.csvW.Flush()
		return wr.csvW.Error()
	}
	return nil
}

// Run starts a dedicated writer goroutine that drains results until the
// channel is closed or ctx is cancelled.  It returns a WaitGroup-style done
// channel that is closed after the final Flush.
//
// This is the recommended way to wire the probe pool into file / stdout
// output without file-lock races.
func (wr *Writer) Run(ctx context.Context, results <-chan prober.AssetResult) <-chan error {
	errCh := make(chan error, 1)

	go func() {
		defer close(errCh)

		var writeErr error
		for {
			select {
			case <-ctx.Done():
				_ = wr.Flush()
				return
			case a, ok := <-results:
				if !ok {
					if err := wr.Flush(); err != nil && writeErr == nil {
						errCh <- err
					} else if writeErr != nil {
						errCh <- writeErr
					}
					return
				}
				if err := wr.Write(a); err != nil && writeErr == nil {
					writeErr = err
				}
			}
		}
	}()

	return errCh
}

// ---------------------------------------------------------------------------
// Formatters
// ---------------------------------------------------------------------------

func (wr *Writer) writeText(a prober.AssetResult) error {
	status := fmt.Sprintf("%d", a.StatusCode)
	title := a.Title
	if title == "" {
		title = "-"
	}
	server := a.Server
	if server == "" {
		server = "-"
	}
	ips := strings.Join(a.IPs, ",")
	if ips == "" {
		ips = "-"
	}

	elapsed := a.ResponseTime.Round(time.Millisecond).String()

	var line string
	if wr.color {
		line = fmt.Sprintf("%s[HTTP]%s %s%-3s%s  %s%-8s%s  %s%s%s  %stitle=%q%s  %sserver=%s%s  %sips=[%s]%s  %s(%s)%s\n",
			colorGreen, colorReset,
			colorYellow, status, colorReset,
			colorDim, elapsed, colorReset,
			colorCyan, a.URL, colorReset,
			colorDim, title, colorReset,
			colorDim, server, colorReset,
			colorDim, ips, colorReset,
			colorDim, formatBytes(a.ContentLength), colorReset,
		)
	} else {
		line = fmt.Sprintf("[HTTP] %-3d  %-8s  %s  title=%q  server=%s  ips=[%s]  (%s)\n",
			a.StatusCode,
			elapsed,
			a.URL,
			title,
			server,
			ips,
			formatBytes(a.ContentLength),
		)
	}

	_, err := io.WriteString(wr.w, line)
	return err
}

func (wr *Writer) writeJSON(a prober.AssetResult) error {
	// Encode via a DTO so response_time is a human-readable string rather
	// than raw nanoseconds.
	dto := struct {
		Host          string   `json:"host"`
		IPs           []string `json:"ips"`
		URL           string   `json:"url"`
		StatusCode    int      `json:"status_code"`
		Title         string   `json:"title"`
		Server        string   `json:"server"`
		ContentLength int64    `json:"content_length"`
		ResponseTime  string   `json:"response_time"`
	}{
		Host:          a.Host,
		IPs:           a.IPs,
		URL:           a.URL,
		StatusCode:    a.StatusCode,
		Title:         a.Title,
		Server:        a.Server,
		ContentLength: a.ContentLength,
		ResponseTime:  a.ResponseTime.String(),
	}
	if dto.IPs == nil {
		dto.IPs = []string{}
	}

	enc := json.NewEncoder(wr.w)
	enc.SetEscapeHTML(false)
	return enc.Encode(dto) // Encode appends a trailing newline → JSON Lines
}

func (wr *Writer) writeCSV(a prober.AssetResult) error {
	if !wr.csvHdr {
		if err := wr.csvW.Write([]string{
			"Host", "IPs", "URL", "StatusCode", "Title", "Server", "ContentLength",
		}); err != nil {
			return err
		}
		wr.csvHdr = true
	}

	return wr.csvW.Write([]string{
		a.Host,
		strings.Join(a.IPs, ";"),
		a.URL,
		fmt.Sprintf("%d", a.StatusCode),
		a.Title,
		a.Server,
		fmt.Sprintf("%d", a.ContentLength),
	})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func wantColor(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func formatBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1fMB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1fKB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%dB", n)
	}
}
