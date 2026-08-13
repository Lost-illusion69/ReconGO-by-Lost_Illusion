// ReconGo — production-grade concurrent asset reconnaissance engine.
//
// Usage:
//
//	recongo -domain example.com [-workers 50] [-dns-workers 100] [-timeout 5s] \
//	  [-probe] [-mutate] [-cluster] [-max-mutations 500] \
//	  [-probe-workers 50] [-http-timeout 5s] [-o results.jsonl] [-format json]
//
// The binary exits with code 0 on success, 1 on usage/config errors,
// and 2 when terminated by signal.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Lost-illusion69/recongo/internal/archive"
	"github.com/Lost-illusion69/recongo/internal/clustering"
	"github.com/Lost-illusion69/recongo/internal/mutator"
	"github.com/Lost-illusion69/recongo/internal/notify"
	"github.com/Lost-illusion69/recongo/internal/origin"
	"github.com/Lost-illusion69/recongo/pkg/dns"
	"github.com/Lost-illusion69/recongo/pkg/engine"
	"github.com/Lost-illusion69/recongo/pkg/output"
	"github.com/Lost-illusion69/recongo/pkg/prober"
	"github.com/Lost-illusion69/recongo/pkg/sources"
)

// version is stamped at build time via -ldflags="-X main.version=<tag>".
// Falls back to "dev" when running via `go run`.
var version = "dev"

// ---------------------------------------------------------------------------
// CLI flags
// ---------------------------------------------------------------------------

// config holds every value parsed from the command line.  It is defined as
// a plain struct (not a global) and passed by pointer throughout the call
// chain so each layer only sees what it needs.
type config struct {
	domain         string
	workers        int
	dnsWorkers     int
	timeout        time.Duration
	resolvers      string // comma-separated "host:port" list
	verbose        bool
	showVersion    bool
	probe          bool
	outputPath     string
	format         string
	httpTimeout    time.Duration
	probeWorkers   int
	mutate         bool
	cluster        bool
	maxMutations   int
	delay          time.Duration
	randomAgent    bool
	headers        string
	proxy          string
	archive        bool
	findOrigin     bool
	takeover       bool
	slackWebhook   string
	discordWebhook string
}

func parseFlags(args []string) (*config, error) {
	fs := flag.NewFlagSet("recongo", flag.ContinueOnError)

	cfg := &config{}

	fs.StringVar(&cfg.domain, "domain", "", "Target domain to enumerate (required)")
	fs.IntVar(&cfg.workers, "workers", 50, "Number of concurrent source-fetch workers")
	fs.IntVar(&cfg.dnsWorkers, "dns-workers", 100, "Number of concurrent DNS resolution workers")
	fs.DurationVar(&cfg.timeout, "timeout", 5*time.Second, "Per-lookup DNS timeout")
	fs.StringVar(&cfg.resolvers, "resolvers", "", "Comma-separated custom DNS resolvers (e.g. 8.8.8.8:53,1.1.1.1:53)")
	fs.BoolVar(&cfg.verbose, "verbose", false, "Enable debug-level logging")
	fs.BoolVar(&cfg.showVersion, "version", false, "Print version and exit")
	fs.BoolVar(&cfg.probe, "probe", true, "Enable HTTP probing on resolved hosts")
	fs.StringVar(&cfg.outputPath, "o", "", "Output file path (default: stdout)")
	fs.StringVar(&cfg.format, "format", "text", "Output format: text, json, or csv")
	fs.DurationVar(&cfg.httpTimeout, "http-timeout", 5*time.Second, "Per-host HTTP probe timeout")
	fs.IntVar(&cfg.probeWorkers, "probe-workers", 50, "Number of concurrent HTTP probe workers")
	mutateFlag := fs.Bool("mutate", true, "Enable pattern mutation engine for candidate generation")
	clusterFlag := fs.Bool("cluster", true, "Enable favicon and response body MMH3 clustering")
	fs.IntVar(&cfg.maxMutations, "max-mutations", 500, "Global cap on emitted mutation candidates")
	fs.DurationVar(&cfg.delay, "delay", 0, "Base per-request delay with jitter (e.g. 100ms, 500ms)")
	randomAgentFlag := fs.Bool("random-agent", true, "Rotate realistic User-Agent strings per request")
	fs.StringVar(&cfg.headers, "headers", "", "Comma-separated custom headers (e.g. \"Authorization: Bearer xyz, X-Forwarded-For: 127.0.0.1\")")
	fs.StringVar(&cfg.proxy, "proxy", "", "HTTP/HTTPS/SOCKS5 proxy URL for probe traffic")
	archiveFlag := fs.Bool("archive", true, "Enable historical archive mining (Wayback Machine + OTX)")
	findOriginFlag := fs.Bool("find-origin", true, "Enable origin IP discovery and CDN bypass correlation")
	takeoverFlag := fs.Bool("takeover", true, "Enable subdomain takeover CNAME verification")
	fs.StringVar(&cfg.slackWebhook, "slack-webhook", "", "Slack incoming webhook URL for scan completion alerts")
	fs.StringVar(&cfg.discordWebhook, "discord-webhook", "", "Discord webhook URL for scan completion alerts")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	cfg.mutate = *mutateFlag
	cfg.cluster = *clusterFlag
	cfg.randomAgent = *randomAgentFlag
	cfg.archive = *archiveFlag
	cfg.findOrigin = *findOriginFlag
	cfg.takeover = *takeoverFlag

	return cfg, nil
}

// ---------------------------------------------------------------------------
// Logger construction
// ---------------------------------------------------------------------------

func buildLogger(verbose bool) *slog.Logger {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}

	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	})

	return slog.New(handler)
}

// ---------------------------------------------------------------------------
// Source registry
// ---------------------------------------------------------------------------

// registeredSources returns the list of all active Source implementations.
// Adding a new integration is as simple as appending it here.
func registeredSources() []sources.Source {
	return []sources.Source{
		sources.NewCrtSh(),        // Certificate Transparency logs
		sources.NewAlienVault(),   // OTX passive DNS (reliable fallback)
		sources.NewHackerTarget(), // HackerTarget host search
		sources.NewWordlist(),     // Local common prefix generator
	}
}

// ---------------------------------------------------------------------------
// Pipeline wiring
// ---------------------------------------------------------------------------

// run wires the engine, DNS resolver, optional HTTP prober, and output writer
// into a single pipeline and blocks until all results are processed or ctx
// is cancelled.
//
//	domains → engine (sources) → dns → [prober] → output writer
func run(ctx context.Context, cfg *config, log *slog.Logger) error {
	format, err := output.ParseFormat(cfg.format)
	if err != nil {
		return err
	}

	var archiveFindings *archive.Findings
	if cfg.archive {
		fmt.Fprintf(os.Stderr, "  [archive] querying Wayback Machine + OTX for %s\n", cfg.domain)
		archiveFindings, err = archive.Query(ctx, cfg.domain, archive.NewClient())
		if err != nil {
			log.WarnContext(ctx, "archive mining failed", slog.String("error", err.Error()))
		} else {
			fmt.Fprintf(os.Stderr, "  [archive] %d subdomains, %d URLs, %d params\n",
				len(archiveFindings.Subdomains), len(archiveFindings.HistoricalURLs), len(archiveFindings.DiscoveredParams))
		}
	}

	var originFindings *origin.Findings
	if cfg.findOrigin {
		fmt.Fprintf(os.Stderr, "  [origin] parsing MX/SPF for %s\n", cfg.domain)
		originFindings, err = origin.Discover(ctx, cfg.domain, nil)
		if err != nil {
			log.WarnContext(ctx, "origin discovery failed", slog.String("error", err.Error()))
		} else if originFindings != nil {
			fmt.Fprintf(os.Stderr, "  [origin] %d candidate IP(s) from mail/SPF records\n", len(originFindings.CandidateIPs))
		}
	}

	// Build the list of custom nameservers (empty = system default).
	var nameservers []string
	if cfg.resolvers != "" {
		for _, r := range strings.Split(cfg.resolvers, ",") {
			r = strings.TrimSpace(r)
			if r != "" {
				nameservers = append(nameservers, r)
			}
		}
	}

	// Construct the DNS resolver.
	resolver, err := dns.NewResolver(dns.Config{
		Nameservers: nameservers,
		Workers:     cfg.dnsWorkers,
		Timeout:     cfg.timeout,
	})
	if err != nil {
		return fmt.Errorf("dns resolver init: %w", err)
	}

	// Construct the source-fetch engine.
	eng := engine.New(
		engine.Config{
			Workers:          cfg.workers,
			ResultBufferSize: cfg.workers * 10,
		},
		registeredSources(),
		log,
	)

	// Seed the domains channel with the single target domain.
	// In a future revision this channel can be fed by a file reader,
	// a pipe, or a stdin scanner without changing any other layer.
	domainCh := make(chan string, 1)
	go func() {
		defer close(domainCh)
		select {
		case domainCh <- cfg.domain:
		case <-ctx.Done():
		}
	}()

	// Stage 1: source fetching  →  raw asset strings.
	resultCh := eng.Run(ctx, domainCh)

	// Stage 2: deduplicate across sources, print each unique discovery, and
	// pipe into the DNS resolver.
	//
	// Both crtsh and alienvault may return overlapping subdomains.  The seen
	// map ensures each unique FQDN is only resolved once, even when multiple
	// sources report the same host.  This goroutine is the single owner of
	// seen so no mutex is needed.
	//
	// Discovery progress goes to stderr when using structured formats so
	// stdout / -o stays clean for piping.
	var workerSeq atomic.Uint64
	hostCh := make(chan string, cfg.dnsWorkers)
	mutatorEng := mutator.New(mutator.Config{
		MaxMutations: cfg.maxMutations,
		RootDomain:   cfg.domain,
	})
	progressOut := os.Stderr
	go func() {
		defer close(hostCh)
		seen := make(map[string]struct{})

		emit := func(host, source string) {
			if _, dup := seen[host]; dup {
				return
			}
			seen[host] = struct{}{}
			n := workerSeq.Add(1)
			fmt.Fprintf(progressOut, "  ▸ [%03d] %-48s  %s\n", n, host, formatSource(source))
			select {
			case hostCh <- host:
			case <-ctx.Done():
			}
		}

		if archiveFindings != nil {
			for _, sub := range archiveFindings.Subdomains {
				emit(sub, "archive")
				if cfg.mutate {
					mutatorEng.Mutate(ctx, sub, hostCh)
				}
			}
		}

		for r := range resultCh {
			if _, dup := seen[r.Value]; dup {
				log.DebugContext(ctx, "skipping duplicate",
					slog.String("host", r.Value),
					slog.String("source", r.Source),
				)
				continue
			}
			emit(r.Value, r.Source)

			if cfg.mutate {
				mutatorEng.Mutate(ctx, r.Value, hostCh)
			}
		}
	}()

	// Stage 3: resolve.
	resolvedCh := resolver.ResolveAll(ctx, hostCh)

	if !cfg.probe {
		return drainResolved(ctx, log, resolvedCh, format)
	}

	probeHeaders, err := prober.ParseHeaders(cfg.headers)
	if err != nil {
		return fmt.Errorf("parse headers: %w", err)
	}

	// Stage 4: HTTP probe alive hosts.
	pool := engine.NewProbePool(engine.ProbeConfig{
		Workers: cfg.probeWorkers,
		Timeout: cfg.httpTimeout,
		Options: prober.Options{
			Delay:          cfg.delay,
			RandomAgent:    cfg.randomAgent,
			Verbose:        cfg.verbose,
			FindOrigin:     cfg.findOrigin,
			OriginFindings: originFindings,
			Headers:        probeHeaders,
			ProxyURL:       cfg.proxy,
		},
	}, log)
	assetCh := pool.Run(ctx, resolvedCh)

	clusterer := clustering.New()
	taggedCh := make(chan prober.AssetResult, cfg.probeWorkers)
	var found atomic.Int64
	var totalEndpoints atomic.Int64
	go func() {
		defer close(taggedCh)
		for a := range assetCh {
			if archiveFindings != nil {
				a.HistoricalURLs, a.DiscoveredParams = archive.FilterForHost(archiveFindings, a.Host)
			}
			if cfg.takeover {
				risk, cname := origin.TakeoverRisk(ctx, a.Host, nil)
				a.TakeoverRisk = risk
				a.TakeoverCNAME = cname
				if risk {
					fmt.Fprintf(os.Stderr, "  [takeover] %-48s  CNAME → %s\n", a.Host, cname)
				}
			}
			if cfg.cluster {
				clusterer.Tag(&a)
			}
			found.Add(1)
			totalEndpoints.Add(int64(len(a.Endpoints)))
			select {
			case taggedCh <- a:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Stage 5: structured export via a dedicated writer goroutine.
	dest, closer, err := openOutput(cfg.outputPath)
	if err != nil {
		return err
	}
	if closer != nil {
		defer func() { _ = closer() }()
	}

	wr := output.NewWriter(format, dest)
	wr.SetMeta(output.ScanMeta{
		Domain:    cfg.domain,
		StartedAt: time.Now(),
		Workers:   cfg.probeWorkers,
	})
	if err := <-wr.Run(ctx, taggedCh); err != nil {
		return fmt.Errorf("output writer: %w", err)
	}

	log.InfoContext(ctx, "scan complete",
		slog.Int64("probed", found.Load()),
		slog.Int64("mutations", mutatorEng.Emitted()),
		slog.String("format", string(format)),
	)

	summary := notify.Summary{
		Domain:    cfg.domain,
		Probed:    found.Load(),
		Endpoints: int(totalEndpoints.Load()),
		Mutations: mutatorEng.Emitted(),
	}
	if err := notify.SendSlack(ctx, cfg.slackWebhook, summary); err != nil {
		log.WarnContext(ctx, "slack webhook failed", slog.String("error", err.Error()))
	}
	if err := notify.SendDiscord(ctx, cfg.discordWebhook, summary); err != nil {
		log.WarnContext(ctx, "discord webhook failed", slog.String("error", err.Error()))
	}
	return nil
}

// drainResolved handles the -probe=false path: print alive hosts to stdout.
func drainResolved(ctx context.Context, log *slog.Logger, resolvedCh <-chan dns.LookupResult, format output.Format) error {
	found := 0
	out := os.Stderr
	for lr := range resolvedCh {
		if lr.Err != nil {
			log.DebugContext(ctx, "dns lookup failed",
				slog.String("host", lr.Host),
				slog.String("error", lr.Err.Error()),
			)
			continue
		}
		found++
		fmt.Fprintf(out, "[ALIVE] %s -> [%s]\n", lr.Host, strings.Join(lr.IPs, ", "))
	}
	log.InfoContext(ctx, "scan complete", slog.Int("resolved", found), slog.String("format", string(format)))
	return nil
}

// openOutput returns the destination writer for formatted results.
// empty, results go to stdout.  The closer must be called when non-nil.
func openOutput(path string) (io.Writer, func() error, error) {
	if path == "" {
		return os.Stdout, nil, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open output file: %w", err)
	}
	return f, f.Close, nil
}

// formatSource returns a compact, aligned source label for discovery lines.
func formatSource(src string) string {
	switch strings.ToLower(src) {
	case "crtsh", "crt.sh":
		return "crt.sh"
	case "alienvault", "otx":
		return "AlienVault OTX"
	case "hackertarget":
		return "HackerTarget"
	case "wordlist":
		return "Wordlist"
	case "archive":
		return "Archive"
	default:
		return src
	}
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

func main() {
	cfg, err := parseFlags(os.Args[1:])
	if err != nil {
		// flag.ContinueOnError already printed the error.
		if strings.Contains(err.Error(), "provided but not defined") {
			fmt.Fprintln(os.Stderr, "hint: unknown flag — run `git pull origin main` to update ReconGo")
		}
		os.Exit(1)
	}

	if cfg.showVersion {
		fmt.Fprintf(os.Stderr, "recongo %s\n", version)
		os.Exit(0)
	}

	if cfg.domain == "" {
		fmt.Fprintln(os.Stderr, "error: -domain is required")
		fmt.Fprintln(os.Stderr, "usage: recongo -domain <target> [options]")
		os.Exit(1)
	}

	if _, err := output.ParseFormat(cfg.format); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	log := buildLogger(cfg.verbose)

	// Root context cancelled on SIGINT / SIGTERM so every goroutine can
	// detect shutdown via ctx.Done() — no global state required.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Info("recongo starting",
		slog.String("version", version),
		slog.String("domain", cfg.domain),
		slog.Int("workers", cfg.workers),
		slog.Int("dns-workers", cfg.dnsWorkers),
		slog.Bool("probe", cfg.probe),
		slog.Bool("mutate", cfg.mutate),
		slog.Bool("cluster", cfg.cluster),
		slog.Int("max-mutations", cfg.maxMutations),
		slog.Int("probe-workers", cfg.probeWorkers),
		slog.String("format", cfg.format),
		slog.Duration("delay", cfg.delay),
		slog.Bool("random-agent", cfg.randomAgent),
		slog.Bool("archive", cfg.archive),
		slog.Bool("find-origin", cfg.findOrigin),
		slog.Bool("takeover", cfg.takeover),
	)
	fmt.Fprintf(os.Stderr, "\n  ReconGO %s — discovery phase\n  Target: %s\n\n", version, cfg.domain)

	if err := run(ctx, cfg, log); err != nil {
		log.Error("fatal", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// Distinguish clean exit from signal-induced exit so callers / scripts
	// can detect cancellation vs. genuine completion.
	if ctx.Err() != nil {
		log.Warn("terminated by signal")
		os.Exit(2)
	}
}
