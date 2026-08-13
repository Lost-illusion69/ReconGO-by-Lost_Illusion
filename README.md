<div align="center">

# ReconGo

**High-Performance Concurrent Asset Discovery & Attack-Surface Profiling Engine in Go.**

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
- [Defensive & Blue Team Context](#defensive--blue-team-context)
- [CI / CD](#ci--cd)
- [License](#license)

---

## Overview

ReconGo is a production-grade CLI that orchestrates **passive subdomain discovery**, **concurrent DNS resolution**, and **active HTTP probing** through a single, channel-driven pipeline. Every stage is bounded by worker pools and context deadlines — designed to scale without goroutine leaks or memory spikes.

Built entirely on the **Go standard library** (zero third-party dependencies), ReconGo ships as a statically linked binary and a hardened multi-stage Docker image.

> **Legal notice:** Use ReconGo only on systems you own or have explicit written permission to assess. Unauthorized scanning is illegal. The authors accept no liability for misuse.

---

## Architecture

ReconGo follows a **clean, concurrent pipeline** where each stage owns its channels and hands work to the next via buffered Go channels. Cancellation propagates through `context.Context` from SIGINT/SIGTERM.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Stage 1 — Passive Source Fetch (pkg/engine)                              │
│  APIs: crt.sh · AlienVault OTX · HackerTarget · built-in Wordlist           │
│  Bounded worker pool fans out Source.Fetch(domain) per registered source    │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │  chan sources.Result
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  Stage 2 — Deduplication Goroutine (map owner, single goroutine)          │
│  In-memory seen{} map · no mutex · emits each unique FQDN exactly once      │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │  dnsJobs channel
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  Stage 3 — Concurrent DNS Worker Pool (pkg/dns, default 100 workers)      │
│  A/AAAA lookups · per-lookup timeout · custom resolvers supported           │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │  probeJobs channel (alive hosts only)
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  Stage 4 — HTTP Web Prober Pool (pkg/prober, default 50 workers)          │
│  HTTPS-first · HTTP fallback · TLS skip-verify · <title> extraction         │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │  results channel
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  Stage 5 — Dedicated Writer Goroutine (pkg/output)                        │
│  Concurrent-safe serialisation → Console · JSON Lines · CSV · file (-o)   │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Simplified data-flow view:**

```
[APIs (crt.sh, OTX, HackerTarget) + Wordlist]
              │
              ▼
[Stage 2 Deduplication Goroutine (Map Owner)]
              │
              ▼  dnsJobs channel
[Concurrent DNS Worker Pool (50 workers)]
              │
              ▼  probeJobs channel
[HTTP Web Prober Pool (50 workers)]
              │
              ▼
[Dedicated Writer Goroutine] ──► [JSON / CSV / Console]
```

Every hand-off is **non-blocking and back-pressure aware** — the pipeline passes `go test -race ./...` with zero data races.

---

## Key Features

| Capability | Detail |
|---|---|
| **Non-blocking concurrent pipeline** | Channel-driven stages with bounded semaphores; validated under the Go race detector |
| **Resilient multi-source fallback** | Four passive sources; per-source failures (HTTP 5xx, 429 rate limits, timeouts) are logged and skipped — remaining sources continue |
| **Thread-safe deduplication** | A dedicated owner goroutine holds the `seen` map; no mutex contention on the hot path |
| **HTTP probing** | HTTPS-first with HTTP fallback, `InsecureSkipVerify` for self-signed certs, configurable `-http-timeout`, HTML `<title>` extraction, 1 MiB body cap |
| **Multi-format exporters** | Plaintext (coloured on TTY), JSON Lines (`-format json`), CSV (`-format csv`), optional file output via `-o` |
| **Graceful shutdown** | `signal.NotifyContext` cancels in-flight work on SIGINT/SIGTERM |
| **Zero dependencies** | Pure stdlib — fast builds, minimal supply-chain risk |
| **Container-ready** | Multi-stage Alpine Dockerfile, non-root `recongo` user, bundled CA certificates |

---

## Quickstart & Installation

### Prerequisites

- Go **1.22+** (local builds)
- Docker (optional, containerised runs)

### Build from source

```bash
git clone https://github.com/Lost-illusion69/ReconGO-by-Lost_Illusion.git
cd ReconGO-by-Lost_Illusion
go build -o recongo ./cmd/recongo
./recongo -domain example.com
```

### Run with Docker

```bash
docker build -t recongo .
docker run --rm recongo -domain target.com
docker run --rm recongo -domain target.com -format json -o /dev/stdout
```

### Run the test suite (race detector)

```bash
go test -v -race ./...
```

---

## CLI Flag Reference

| Flag | Type | Default | Description |
|---|---|---|---|
| `-domain` | string | *(required)* | Target root domain to enumerate (e.g. `example.com`) |
| `-workers` | int | `50` | Number of concurrent source-fetch workers |
| `-probe` | bool | `true` | Enable active HTTP probing on DNS-alive hosts |
| `-format` | string | `text` | Output format: `text`, `json`, or `csv` |
| `-o` | string | *(stdout)* | Write structured results to a file path |
| `-verbose` | bool | `false` | Enable debug-level structured logging (`log/slog`) |

<details>
<summary><strong>Advanced flags</strong></summary>

| Flag | Type | Default | Description |
|---|---|---|---|
| `-dns-workers` | int | `100` | Concurrent DNS resolution workers |
| `-probe-workers` | int | `50` | Concurrent HTTP probe workers |
| `-http-timeout` | duration | `5s` | Per-host HTTP probe deadline |
| `-timeout` | duration | `5s` | Per-lookup DNS timeout |
| `-resolvers` | string | *(system)* | Comma-separated custom resolvers (`8.8.8.8:53,1.1.1.1:53`) |
| `-version` | bool | `false` | Print version and exit |

</details>

---

## Usage Examples

```bash
# Full pipeline: passive sources → DNS → HTTP probe → console
recongo -domain example.com

# JSON Lines export to file
recongo -domain example.com -format json -o results.jsonl

# CSV export, higher probe concurrency
recongo -domain example.com -format csv -o assets.csv -probe-workers 100

# DNS-only mode (skip HTTP probing)
recongo -domain example.com -probe=false

# Custom resolvers + verbose debug logging
recongo -domain example.com \
  -resolvers "8.8.8.8:53,1.1.1.1:53" \
  -verbose
```

---

## Defensive & Blue Team Context

> Written for **SOC analysts, threat hunters, and blue teamers** who may observe ReconGo (or similar tooling) against their estate. Knowing how recon tools behave on the wire is essential for effective detection engineering.

### Network observables

| Signal | What to look for |
|---|---|
| **DNS enumeration burst** | A single host IP fires dozens–hundreds of `A`/`AAAA` queries per minute against unique subdomains (`api.`, `dev.`, `staging.`, `mail.`, …) |
| **Non-corporate resolvers** | Outbound UDP/53 to public resolvers (8.8.8.8, 1.1.1.1) instead of internal DNS |
| **Passive API polling** | Outbound HTTPS to `crt.sh`, `otx.alienvault.com`, `api.hackertarget.com` from a non-browser process |
| **HTTP probing sweep** | Rapid sequential `GET` requests to `:443`/`:80` across many hostnames from one source, often with a distinctive User-Agent |
| **CT log correlation** | New certificate issuance for your domain appearing in CT feeds shortly before inbound scan traffic |

### Sigma rule — rapid DNS query spike (Windows Sysmon Event ID 22)

Detects a single process emitting an abnormal volume of DNS queries — consistent with subdomain enumeration tools such as ReconGo, Subfinder, or Amass.

```yaml
title: Rapid DNS Resolution — Possible Subdomain Enumeration
id: a3f7c812-3e4d-4b9a-8f1c-7d2e6a0b5c9f
status: experimental
description: >
  Detects a high volume of DNS queries originating from a single process
  in a short time window, consistent with automated subdomain enumeration
  tools such as ReconGo, amass, subfinder, or gobuster DNS mode.
references:
  - https://github.com/Lost-illusion69/ReconGO-by-Lost_Illusion
  - https://attack.mitre.org/techniques/T1018/
  - https://attack.mitre.org/techniques/T1595/001/
author: Lost-illusion69
date: 2026-08-13
tags:
  - attack.reconnaissance
  - attack.t1595.001
  - attack.t1018
logsource:
  product: windows
  category: dns_query          # Sysmon Event ID 22
detection:
  selection:
    EventID: 22
  timeframe: 10s
  condition: selection | count() by ProcessId, Image > 50
falsepositives:
  - Software updaters resolving many CDN hostnames
  - Browser prefetch on developer workstations
  - Internal service-discovery (Consul, Kubernetes DNS)
level: medium
fields:
  - Image
  - QueryName
  - QueryResults
  - ProcessId
  - User
```

### HTTP probing detection

ReconGo sets an explicit User-Agent on probe requests:

```
ReconGo/1.0 (+https://github.com/Lost-illusion69/recongo)
```

Passive source API calls use a similar fingerprint:

```
ReconGo/1.0 (github.com/Lost-illusion69/recongo)
```

**Detection ideas:**

| Layer | Rule concept |
|---|---|
| **WAF / reverse proxy** | Alert on >N distinct hostnames requested by one source IP within 60 s on ports 80/443 |
| **NDR / Zeek** | `http.log` — group by `id.orig_h`, count unique `host` values; threshold > 50/min |
| **SIEM** | Correlate DNS query burst (Event ID 22) followed within 5 min by outbound HTTP GET fan-out to the same FQDN set |
| **User-Agent match** | `User-Agent` contains `ReconGo/1.0` — high-fidelity but trivially spoofed; use as enrichment, not sole signal |

### Recommended mitigations

| Control | Implementation |
|---|---|
| **DNS rate limiting** | Per-source-IP limits on recursive resolvers (Unbound, BIND, Windows DNS) |
| **RPZ** | Response Policy Zones to sinkhole or redirect suspicious enumeration patterns |
| **CT monitoring** | Alert on new certificates issued for your domains via crt.sh / Google CT |
| **Egress filtering** | Restrict outbound DNS to authorised resolvers only |
| **WAF rate rules** | Per-IP request limits on edge for rapid hostname scanning |

---

## CI / CD

Every push to `main` and every pull request triggers [`.github/workflows/ci.yml`](.github/workflows/ci.yml):

| Step | Purpose |
|---|---|
| `gofmt -s -l .` | Enforce simplified, canonical Go formatting |
| `go test -v -race ./...` | Full test suite under the race detector |
| `go build -v -o recongo ./cmd/recongo` | Verify release binary compiles cleanly |

---

## License

MIT © 2026 [Lost-illusion69](https://github.com/Lost-illusion69)
