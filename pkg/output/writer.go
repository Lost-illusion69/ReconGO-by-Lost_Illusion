// Package output provides concurrent-safe exporters for probed assets.
//
// Supported formats:
//   - text  — premium boxed cards with status badges
//   - json  — structured JSON Lines (one record per line)
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

// ScanMeta holds scan-level metadata for banners and summaries.
type ScanMeta struct {
	Domain    string
	StartedAt time.Time
	Workers   int
}

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

// ANSI colour codes — disabled when destination is not a TTY or NO_COLOR is set.
const (
	colorReset  = "\033[0m"
	colorGreen  = "\033[32m"
	colorCyan   = "\033[36m"
	colorYellow = "\033[33m"
	colorRed    = "\033[31m"
	colorBlue   = "\033[34m"
	colorDim    = "\033[2m"
	colorBold   = "\033[1m"
)

// Writer serialises AssetResult values to an io.Writer in the chosen format.
type Writer struct {
	format Format
	w      io.Writer
	color  bool
	meta   ScanMeta

	mu     sync.Mutex
	csvHdr bool
	csvW   *csv.Writer

	// collected for text-mode summary footer
	results []prober.AssetResult
}

// NewWriter constructs a Writer that encodes into w using format.
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

// SetMeta attaches scan metadata for text banners and summaries.
func (wr *Writer) SetMeta(m ScanMeta) {
	wr.meta = m
}

// WriteHeader prints the scan banner (text mode only).
func (wr *Writer) WriteHeader() error {
	if wr.format != FormatText {
		return nil
	}
	wr.mu.Lock()
	defer wr.mu.Unlock()
	_, err := io.WriteString(wr.w, renderBanner(wr.meta, wr.color))
	return err
}

// OpenFile creates (or truncates) path and returns a Writer bound to it.
func OpenFile(format Format, path string) (*Writer, func() error, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, fmt.Errorf("output: create %s: %w", path, err)
	}
	return NewWriter(format, f), f.Close, nil
}

// Write encodes a single AssetResult. Safe for concurrent use; prefer Run for pipelines.
func (wr *Writer) Write(a prober.AssetResult) error {
	wr.mu.Lock()
	defer wr.mu.Unlock()

	if wr.format == FormatText {
		wr.results = append(wr.results, a)
	}

	switch wr.format {
	case FormatJSON:
		return wr.writeJSON(a)
	case FormatCSV:
		return wr.writeCSV(a)
	default:
		return wr.writeText(a)
	}
}

// Flush ensures buffered CSV data and text summary reach the underlying writer.
func (wr *Writer) Flush() error {
	wr.mu.Lock()
	defer wr.mu.Unlock()

	if wr.format == FormatText && len(wr.results) > 0 {
		if _, err := io.WriteString(wr.w, renderSummary(wr.meta, wr.results, wr.color)); err != nil {
			return err
		}
	}

	if wr.csvW != nil {
		wr.csvW.Flush()
		return wr.csvW.Error()
	}
	return nil
}

// Run drains results until the channel closes or ctx is cancelled.
func (wr *Writer) Run(ctx context.Context, results <-chan prober.AssetResult) <-chan error {
	errCh := make(chan error, 1)

	go func() {
		defer close(errCh)

		if err := wr.WriteHeader(); err != nil {
			errCh <- err
			return
		}

		var writeErr error
		for {
			select {
			case <-ctx.Done():
				if err := wr.Flush(); err != nil && writeErr == nil {
					writeErr = err
				}
				if writeErr != nil {
					errCh <- writeErr
				}
				return
			case a, ok := <-results:
				if !ok {
					if err := wr.Flush(); err != nil && writeErr == nil {
						errCh <- writeErr
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

func (wr *Writer) writeText(a prober.AssetResult) error {
	_, err := io.WriteString(wr.w, renderResultCard(a, wr.color))
	return err
}

func (wr *Writer) writeJSON(a prober.AssetResult) error {
	dto := jsonResult{
		Asset: assetBlock{
			Host: a.Host,
			IPs:  a.IPs,
			URL:  a.URL,
		},
		HTTP: httpBlock{
			StatusCode:    a.StatusCode,
			Title:         a.Title,
			Server:        a.Server,
			ContentLength: a.ContentLength,
			ResponseTime:  a.ResponseTime.String(),
		},
		Fingerprints: fingerprintBlock{
			FaviconMMH3: a.FaviconMMH3,
			BodyMMH3:    a.BodyMMH3,
			ClusterTag:  a.ClusterTag,
		},
		Endpoints:          a.Endpoints,
		HistoricalURLs:     a.HistoricalURLs,
		DiscoveredParams:   a.DiscoveredParams,
		IsCDNProxied:       a.IsCDNProxied,
		CDNProvider:        a.CDNProvider,
		PotentialOriginIPs: a.PotentialOriginIPs,
		TakeoverRisk:       a.TakeoverRisk,
		TakeoverCNAME:      a.TakeoverCNAME,
	}
	if dto.Asset.IPs == nil {
		dto.Asset.IPs = []string{}
	}
	if dto.Endpoints == nil {
		dto.Endpoints = []string{}
	}
	if dto.HistoricalURLs == nil {
		dto.HistoricalURLs = []string{}
	}
	if dto.DiscoveredParams == nil {
		dto.DiscoveredParams = []string{}
	}
	if dto.PotentialOriginIPs == nil {
		dto.PotentialOriginIPs = []string{}
	}

	enc := json.NewEncoder(wr.w)
	enc.SetEscapeHTML(false)
	return enc.Encode(dto)
}

func (wr *Writer) writeCSV(a prober.AssetResult) error {
	if !wr.csvHdr {
		if err := wr.csvW.Write([]string{
			"Host", "IPs", "URL", "StatusCode", "Title", "Server", "ContentLength",
			"ResponseTime", "FaviconMMH3", "BodyMMH3", "ClusterTag", "Endpoints",
			"HistoricalURLs", "DiscoveredParams", "IsCDNProxied", "CDNProvider",
			"PotentialOriginIPs", "TakeoverRisk", "TakeoverCNAME",
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
		a.ResponseTime.String(),
		fmt.Sprintf("%d", a.FaviconMMH3),
		fmt.Sprintf("%d", a.BodyMMH3),
		a.ClusterTag,
		strings.Join(a.Endpoints, ";"),
		strings.Join(a.HistoricalURLs, ";"),
		strings.Join(a.DiscoveredParams, ";"),
		fmt.Sprintf("%t", a.IsCDNProxied),
		a.CDNProvider,
		strings.Join(a.PotentialOriginIPs, ";"),
		fmt.Sprintf("%t", a.TakeoverRisk),
		a.TakeoverCNAME,
	})
}

type jsonResult struct {
	Asset              assetBlock       `json:"asset"`
	HTTP               httpBlock        `json:"http"`
	Fingerprints       fingerprintBlock `json:"fingerprints"`
	Endpoints          []string         `json:"endpoints"`
	HistoricalURLs     []string         `json:"historical_urls"`
	DiscoveredParams   []string         `json:"discovered_params"`
	IsCDNProxied       bool             `json:"is_cdn_proxied"`
	CDNProvider        string           `json:"cdn_provider,omitempty"`
	PotentialOriginIPs []string         `json:"potential_origin_ips"`
	TakeoverRisk       bool             `json:"takeover_risk,omitempty"`
	TakeoverCNAME      string           `json:"takeover_cname,omitempty"`
}

type assetBlock struct {
	Host string   `json:"host"`
	IPs  []string `json:"ips"`
	URL  string   `json:"url"`
}

type httpBlock struct {
	StatusCode    int    `json:"status_code"`
	Title         string `json:"title"`
	Server        string `json:"server"`
	ContentLength int64  `json:"content_length"`
	ResponseTime  string `json:"response_time"`
}

type fingerprintBlock struct {
	FaviconMMH3 int32  `json:"favicon_mmh3,omitempty"`
	BodyMMH3    int32  `json:"body_mmh3,omitempty"`
	ClusterTag  string `json:"cluster_tag,omitempty"`
}

func renderBanner(m ScanMeta, color bool) string {
	title := "ReconGO Scan"
	if m.Domain != "" {
		title = fmt.Sprintf("ReconGO · %s", m.Domain)
	}
	started := m.StartedAt
	if started.IsZero() {
		started = time.Now()
	}

	var b strings.Builder
	b.WriteString("\n")
	if color {
		b.WriteString(colorBold + colorCyan)
	}
	b.WriteString("╔══════════════════════════════════════════════════════════════════════════════╗\n")
	b.WriteString(fmt.Sprintf("║  %-74s ║\n", title))
	b.WriteString("╠══════════════════════════════════════════════════════════════════════════════╣\n")
	b.WriteString(fmt.Sprintf("║  Started   %-65s ║\n", started.UTC().Format(time.RFC3339)))
	if m.Workers > 0 {
		b.WriteString(fmt.Sprintf("║  Workers   %-65d ║\n", m.Workers))
	}
	b.WriteString("╚══════════════════════════════════════════════════════════════════════════════╝\n")
	if color {
		b.WriteString(colorReset)
	}
	b.WriteString("\n")
	return b.String()
}

func renderResultCard(a prober.AssetResult, color bool) string {
	statusBadge := statusLabel(a.StatusCode)
	title := truncate(a.Title, 48)
	if title == "" {
		title = "—"
	}
	server := truncate(a.Server, 28)
	if server == "" {
		server = "—"
	}
	ips := strings.Join(a.IPs, ", ")
	if ips == "" {
		ips = "—"
	}
	elapsed := a.ResponseTime.Round(time.Millisecond).String()
	size := formatBytes(a.ContentLength)

	var b strings.Builder
	if color {
		b.WriteString(colorGreen)
	}
	b.WriteString("┌──────────────────────────────────────────────────────────────────────────────┐\n")
	b.WriteString(fmt.Sprintf("│  %-42s  %12s │\n", truncate(a.Host, 42), statusBadge))
	b.WriteString("├──────────────────────────────────────────────────────────────────────────────┤\n")
	b.WriteString(fmt.Sprintf("│  URL         %-63s │\n", truncate(a.URL, 63)))
	b.WriteString(fmt.Sprintf("│  IP          %-63s │\n", truncate(ips, 63)))
	b.WriteString(fmt.Sprintf("│  Title       %-63s │\n", title))
	b.WriteString(fmt.Sprintf("│  Server      %-63s │\n", server))
	b.WriteString(fmt.Sprintf("│  Response    %-63s │\n", elapsed+" · "+size))

	if a.FaviconMMH3 != 0 || a.BodyMMH3 != 0 || a.ClusterTag != "" {
		b.WriteString("├─ Fingerprints ───────────────────────────────────────────────────────────────┤\n")
		if a.FaviconMMH3 != 0 {
			b.WriteString(fmt.Sprintf("│    favicon_mmh3  %-59d │\n", a.FaviconMMH3))
		}
		if a.BodyMMH3 != 0 {
			b.WriteString(fmt.Sprintf("│    body_mmh3     %-59d │\n", a.BodyMMH3))
		}
		if a.ClusterTag != "" {
			b.WriteString(fmt.Sprintf("│    cluster       %-59s │\n", truncate(a.ClusterTag, 59)))
		}
	}

	b.WriteString("├─ Endpoints ──────────────────────────────────────────────────────────────────┤\n")
	if len(a.Endpoints) > 0 {
		for i, ep := range a.Endpoints {
			if i >= 12 {
				b.WriteString(fmt.Sprintf("│    … +%d more                                                                │\n", len(a.Endpoints)-12))
				break
			}
			b.WriteString(fmt.Sprintf("│    • %-72s │\n", truncate(ep, 72)))
		}
	} else {
		b.WriteString("│    (none discovered)                                                         │\n")
	}

	if a.IsCDNProxied || a.CDNProvider != "" || len(a.PotentialOriginIPs) > 0 {
		b.WriteString("├─ Origin / CDN ───────────────────────────────────────────────────────────────┤\n")
		if a.IsCDNProxied {
			b.WriteString(fmt.Sprintf("│    cdn_proxied   %-59t │\n", a.IsCDNProxied))
		}
		if a.CDNProvider != "" {
			b.WriteString(fmt.Sprintf("│    cdn_provider  %-59s │\n", truncate(a.CDNProvider, 59)))
		}
		for i, ip := range a.PotentialOriginIPs {
			if i >= 4 {
				b.WriteString(fmt.Sprintf("│    … +%d origin candidate(s)                                                  │\n", len(a.PotentialOriginIPs)-4))
				break
			}
			b.WriteString(fmt.Sprintf("│    origin_ip     %-59s │\n", ip))
		}
	}

	if len(a.HistoricalURLs) > 0 || len(a.DiscoveredParams) > 0 {
		b.WriteString("├─ Archive Intel ──────────────────────────────────────────────────────────────┤\n")
		for i, u := range a.HistoricalURLs {
			if i >= 6 {
				b.WriteString(fmt.Sprintf("│    … +%d historical URL(s)                                                    │\n", len(a.HistoricalURLs)-6))
				break
			}
			b.WriteString(fmt.Sprintf("│    url           %-59s │\n", truncate(u, 59)))
		}
		for i, p := range a.DiscoveredParams {
			if i >= 6 {
				break
			}
			b.WriteString(fmt.Sprintf("│    param          %-58s │\n", truncate(p, 58)))
		}
	}

	if a.TakeoverRisk {
		b.WriteString("├─ Takeover ───────────────────────────────────────────────────────────────────┤\n")
		b.WriteString(fmt.Sprintf("│    RISK          CNAME → %-52s │\n", truncate(a.TakeoverCNAME, 52)))
	}

	b.WriteString("└──────────────────────────────────────────────────────────────────────────────┘\n\n")
	if color {
		b.WriteString(colorReset)
	}
	return b.String()
}

func renderSummary(m ScanMeta, results []prober.AssetResult, color bool) string {
	var live, blocked, endpoints int
	for _, r := range results {
		switch {
		case r.StatusCode >= 200 && r.StatusCode < 400:
			live++
		default:
			blocked++
		}
		endpoints += len(r.Endpoints)
	}

	var b strings.Builder
	if color {
		b.WriteString(colorBold + colorBlue)
	}
	b.WriteString("\n")
	b.WriteString("╔══════════════════════════════════════════════════════════════════════════════╗\n")
	b.WriteString("║  SCAN SUMMARY                                                                ║\n")
	b.WriteString("╠══════════════════════════════════════════════════════════════════════════════╣\n")
	b.WriteString(fmt.Sprintf("║  Probed        %-61d ║\n", len(results)))
	b.WriteString(fmt.Sprintf("║  Live (2xx/3xx) %-58d ║\n", live))
	b.WriteString(fmt.Sprintf("║  Blocked/Error %-59d ║\n", blocked))
	b.WriteString(fmt.Sprintf("║  Endpoints     %-61d ║\n", endpoints))
	if m.Domain != "" {
		b.WriteString(fmt.Sprintf("║  Domain        %-61s ║\n", truncate(m.Domain, 61)))
	}
	b.WriteString("╚══════════════════════════════════════════════════════════════════════════════╝\n")
	if color {
		b.WriteString(colorReset)
	}
	return b.String()
}

func statusLabel(code int) string {
	switch {
	case code >= 200 && code < 300:
		return fmt.Sprintf("[%d OK]", code)
	case code >= 300 && code < 400:
		return fmt.Sprintf("[%d REDIR]", code)
	case code >= 400 && code < 500:
		return fmt.Sprintf("[%d CLIENT]", code)
	case code >= 500:
		return fmt.Sprintf("[%d SERVER]", code)
	default:
		return fmt.Sprintf("[%d —]", code)
	}
}

func truncate(s string, max int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.TrimSpace(s)
	if max <= 0 || len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}

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
