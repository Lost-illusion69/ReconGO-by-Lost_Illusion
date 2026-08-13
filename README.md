<div align="center">

# ReconGo

**High-Performance Multi-Protocol Recon & Attack Surface Engine in Go**

[![Go Version](https://img.shields.io/badge/go-1.22+-00ADD8?logo=go&logoColor=white)](go.mod)
[![CI](https://github.com/Lost-illusion69/ReconGO-by-Lost_Illusion/actions/workflows/ci.yml/badge.svg)](https://github.com/Lost-illusion69/ReconGO-by-Lost_Illusion/actions/workflows/ci.yml)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED?logo=docker&logoColor=white)](Dockerfile)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

*A [Lost-illusion69](https://github.com/Lost-illusion69) Security Labs project — built for authorized recon, bug bounty, and red-team workflows.*

</div>

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Key Features](#key-features)
- [Quickstart & Installation](#quickstart--installation)
- [CLI Flag Reference](#cli-flag-reference)
- [Usage Examples](#usage-examples)
- [Output Formats](#output-formats)
- [Defensive & Blue Team Context](#defensive--blue-team-context)
- [CI / CD](#ci--cd)
- [License](#license)

---

## Overview

ReconGo is a production-grade CLI that orchestrates **passive subdomain discovery**, **historical archive mining**, **concurrent DNS resolution**, **HTTP/2 active probing**, **JS endpoint mining**, **CDN/origin correlation**, and **structured export** through a single channel-driven pipeline. Every stage is bounded by worker pools and context deadlines — designed to scale without goroutine leaks or memory spikes.

Built on Go 1.22+ with minimal dependencies (`golang.org/x/net` for HTTP/2), ReconGo ships as a statically linked binary and a hardened multi-stage Docker image.

> **Legal notice:** Use ReconGo only on systems you own or have explicit written permission to assess. Unauthorized scanning is illegal. The authors accept no liability for misuse.

---

## Architecture

```
[Passive Sources: crt.sh · OTX · HackerTarget · Wordlist]
              │
              ▼
[Archive Mining: Wayback CDX · OTX passive DNS / URL list]  (-archive)
              │
              ▼
[Deduplication + Pattern Mutation Engine]                   (-mutate)
              │
              ▼
[Concurrent DNS Worker Pool]                                (-dns-workers)
              │
              ▼
[HTTP/2 Prober Pool + JS Mining + Origin Correlation]       (-probe, -find-origin)
              │
              ▼
[MMH3 Clustering + Takeover Checks + Writer]                (-cluster, -takeover)
              │
              ▼
[stdout: JSON / text / CSV]     [stderr: discovery, logs, progress]
```

**Stdout/stderr separation:** All discovery progress, worker status, archive/origin phase logs, and `log/slog` output go to **stderr**. Formatted probe results (`-format json|text|csv`) go to **stdout** (or `-o`) for clean piping into `jq`, SIEM, or databases.

---

## Key Features

| Capability | Detail |
|---|---|
| **Pattern mutation state machine** | `-mutate` / `-max-mutations` — environment, region, and token permutation engine |
| **Favicon & body MMH3 clustering** | `-cluster` — group assets by visual/content fingerprint similarity |
| **Subdomain takeover verification** | `-takeover` — CNAME dangling-service fingerprint checks |
| **Webhook alerting** | `-slack-webhook` / `-discord-webhook` — scan completion notifications |
| **In-memory JS endpoint mining** | Fetches referenced `.js` bundles and extracts API routes/parameters |
| **Historical archive mining** | `-archive` — Wayback Machine CDX + AlienVault OTX passive DNS & URL lists |
| **Origin IP & CDN bypass** | `-find-origin` — MX/SPF parsing, CDN detection, favicon MMH3 correlation |
| **HTTP/2 probing** | HTTP/2 transport with HTTP/1.1 fallback via `golang.org/x/net/http2` |
| **Adaptive backoff** | Exponential retry on HTTP 429/503 per host |
| **Diagnostic header injection** | `X-Forwarded-For`, `X-Real-IP`, `X-Debug` on probe requests |
| **Adaptive traffic shaping** | `-delay`, `-random-agent`, `-headers`, `-proxy` (HTTP/HTTPS/SOCKS5) |
| **Premium structured output** | Boxed text cards, nested JSON Lines, CSV with full field set |
| **Graceful shutdown** | SIGINT/SIGTERM cancels in-flight work via `context.Context` |

---

## Quickstart & Installation

### Prerequisites

- Go **1.22+**
- Docker (optional)

### Build from source

```bash
git clone https://github.com/Lost-illusion69/ReconGO-by-Lost_Illusion.git
cd ReconGO-by-Lost_Illusion
go build -o recongo ./cmd/recongo
./recongo -domain example.com
```

### Run tests (race detector)

```bash
go test -v -race ./...
```

---

## CLI Flag Reference

| Flag | Type | Default | Description |
|---|---|---|---|
| `-domain` | string | *(required)* | Target root domain to enumerate |
| `-workers` | int | `50` | Concurrent passive source-fetch workers |
| `-dns-workers` | int | `100` | Concurrent DNS resolution workers |
| `-probe-workers` | int | `50` | Concurrent HTTP probe workers |
| `-timeout` | duration | `5s` | Per-lookup DNS timeout |
| `-http-timeout` | duration | `5s` | Per-host HTTP probe deadline |
| `-resolvers` | string | *(system)* | Comma-separated custom DNS resolvers (`8.8.8.8:53`) |
| `-probe` | bool | `true` | Enable HTTP probing on DNS-alive hosts |
| `-mutate` | bool | `true` | Enable pattern mutation candidate generation |
| `-max-mutations` | int | `500` | Global cap on emitted mutation candidates |
| `-cluster` | bool | `true` | Enable favicon/body MMH3 clustering tags |
| `-takeover` | bool | `true` | Enable subdomain takeover CNAME verification |
| `-archive` | bool | `true` | Enable Wayback + OTX historical archive mining |
| `-find-origin` | bool | `true` | Enable MX/SPF origin IP & CDN bypass correlation |
| `-format` | string | `text` | Output format: `text`, `json`, or `csv` |
| `-o` | string | *(stdout)* | Write structured results to file |
| `-delay` | duration | `0` | Base per-request delay with jitter |
| `-random-agent` | bool | `true` | Rotate realistic User-Agent strings |
| `-headers` | string | *(none)* | Comma-separated custom headers (`Key: Value, ...`) |
| `-proxy` | string | *(none)* | HTTP/HTTPS/SOCKS5 proxy URL for probe traffic |
| `-slack-webhook` | string | *(none)* | Slack incoming webhook for scan completion |
| `-discord-webhook` | string | *(none)* | Discord webhook for scan completion |
| `-verbose` | bool | `false` | Debug logging + JS mining stats on stderr |
| `-version` | bool | `false` | Print version and exit |

---

## Usage Examples

### Full pipeline with premium text output

```bash
recongo -domain example.com
# stderr → discovery progress, archive/origin phases
# stdout → boxed result cards + summary footer
```

### Clean JSON Lines for piping (stdout/stderr separation)

```bash
recongo -domain example.com -format json 2>scan.log | tee results.jsonl
```

### Filter live hosts and endpoints with jq

```bash
recongo -domain example.com -format json 2>/dev/null \
  | jq 'select(.http.status_code >= 200 and .http.status_code < 400) | {host: .asset.host, endpoints: .endpoints}'
```

### Archive + origin correlation with file export

```bash
recongo -domain target.com \
  -archive=true -find-origin=true \
  -format json -o results.jsonl \
  2>progress.log
```

### Adaptive traffic through a proxy

```bash
recongo -domain target.com \
  -delay 200ms -random-agent=true \
  -proxy socks5://127.0.0.1:9050 \
  -headers "Authorization: Bearer $TOKEN"
```

### DNS-only mode (no HTTP probe)

```bash
recongo -domain example.com -probe=false 2>&1
# resolved hosts printed to stderr
```

### Slack notification on completion

```bash
recongo -domain example.com \
  -slack-webhook "https://hooks.slack.com/services/XXX/YYY/ZZZ" \
  -format json -o results.jsonl
```

---

## Output Formats

### JSON (JSON Lines)

Each probed host emits one nested JSON object on stdout:

```json
{
  "asset": { "host": "api.example.com", "ips": ["1.2.3.4"], "url": "https://api.example.com" },
  "http": { "status_code": 200, "title": "Portal", "server": "nginx" },
  "fingerprints": { "body_mmh3": 12345, "cluster_tag": "body-1" },
  "endpoints": ["/api/v1/health"],
  "historical_urls": ["/api/v1/users"],
  "discovered_params": ["token", "debug"],
  "is_cdn_proxied": true,
  "cdn_provider": "Cloudflare",
  "potential_origin_ips": ["203.0.113.10"],
  "takeover_risk": false
}
```

### Text

Premium boxed cards with sections for HTTP metadata, fingerprints, endpoints, CDN/origin intel, archive data, and takeover warnings.

### CSV

RFC-4180 CSV with header row including all probe, archive, and origin fields.

---

## Defensive & Blue Team Context

ReconGo emits predictable observables useful for detection engineering:

| Signal | Indicator |
|---|---|
| DNS burst | High-volume `A`/`AAAA` lookups for unique subdomains |
| Passive API polling | HTTPS to `crt.sh`, `web.archive.org`, `otx.alienvault.com` |
| HTTP probe sweep | Rapid `GET` across many hostnames with diagnostic headers |
| User-Agent | `ReconGo/1.0 (+https://github.com/Lost-illusion69/recongo)` |

See the full Sigma rule and mitigation guidance in prior releases for SOC integration patterns.

---

## CI / CD

Every push to `main` and every pull request triggers [`.github/workflows/ci.yml`](.github/workflows/ci.yml):

| Step | Purpose |
|---|---|
| `gofmt -s -l .` | Enforce canonical Go formatting |
| `go test -v -race ./...` | Full suite under the race detector |
| `go build -v -o recongo ./cmd/recongo` | Verify release binary compiles |

---

## License

MIT © 2026 [Lost-illusion69](https://github.com/Lost-illusion69)
