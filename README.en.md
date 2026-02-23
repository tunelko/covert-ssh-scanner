# Covert SSH Scanner

[🇪🇸 Version en espanol](README.md)

Network analysis tool that automatically detects which covert SSH channels are available in a given network environment and recommends the optimal evasion technique.

> **Disclaimer:** This tool has been developed solely for academic and security research purposes. It is intended for use in controlled environments, test labs, and authorized audits only. The author assumes no responsibility for any misuse or illegal use of this tool. Using this tool against systems without explicit authorization from the owner is illegal and may constitute a criminal offense. Use it responsibly and ethically.

---

## Table of contents

1. [What problem does it solve](#what-problem-does-it-solve)
2. [How it works](#how-it-works)
3. [Prerequisites](#prerequisites)
4. [Installation](#installation)
5. [Usage guide](#usage-guide)
   - [First scan (simulation mode)](#1-first-scan-simulation-mode)
   - [Real scan against a target](#2-real-scan-against-a-target)
   - [Generate configurations](#3-generate-configurations)
   - [Steganography module](#4-steganography-module)
6. [Command reference](#command-reference)
7. [Project architecture](#project-architecture)
8. [How the decision engine works](#how-the-decision-engine-works)
9. [Steganography module in detail](#steganography-module-in-detail)
10. [Tests](#tests)
11. [FAQ](#faq)
12. [License](#license)

---

## What problem does it solve

When an operator needs to establish an SSH connection through a hostile network (corporate firewalls, censored networks, hotels, airports...), they face these questions:

- Is port 22 open? Probably not.
- Can I tunnel SSH through port 443? Depends on whether there's DPI.
- Is there an HTTP proxy? Do they intercept TLS? Is DNS filtered?
- Which evasion technique should I use? Stunnel? WebSocket? obfs4? DNS tunnel?

**Covert SSH Scanner** automates all that analysis: it scans the network, detects active restrictions, and recommends the best technique with ready-to-use configurations.

---

## How it works

The tool operates in three sequential phases:

```
 PHASE 1: RECONNAISSANCE        PHASE 2: DECISION          PHASE 3: CONFIGURATION
 =======================        =================          =====================

 TCP Probe (ports)       ──┐                                stunnel.conf
 HTTP Probe (proxy/TLS)  ──┤     Weighted         ──►      wstunnel + nginx
 DNS Probe (filtering)   ──┼──►  scoring           ──►      torrc
 ICMP Probe (ping)       ──┤     engine            ──►      ssh_config
 DPI Probe (inspection)  ──┘     (6 criteria)      ──►      docker-compose.yml

         Real network            8 techniques               Ready-to-use
                                 ranked                     files
```

### Phase 1 — Reconnaissance: "what does this network allow through?"

Five independent probes analyze the network. Each one asks a specific question:

| Probe | What it detects | Requires root |
|---|---|---|
| `tcp_probe` | Open/filtered/closed ports + service banners | No |
| `http_probe` | HTTP proxies (CONNECT and transparent) + TLS interception | No |
| `dns_probe` | DNS manipulation, NXDOMAIN hijacking, DNS tunnel viability | No |
| `icmp_probe` | ICMP allowed, size restrictions, estimated bandwidth | Yes |
| `dpi_probe` | Active DPI (SSH banner on port 443, SSH-in-TLS, protocol enforcement) | No* |

*\*DPI probe uses regular TCP sockets, not raw sockets.*

**TCPProbe** — opens a TCP socket to each port and classifies the response:

```
 Port 22  ──► socket.connect() ──► timeout?          → "filtered"  (firewall drops it)
                                ──► RST?              → "closed"    (host rejects it)
                                ──► connects?         → "open"      + tries to read banner
                                                        "SSH-2.0-..." → SSH service
                                                        "HTTP/1.1..."  → HTTP service
```

**HTTPProbe** — detects intermediaries in the network path:

```
 Test 1: CONNECT proxy                    Test 2: TLS interception
 ─────────────────────                    ────────────────────────
 Sends "CONNECT domain:443"              Connects TLS to :443
 to target's port 80                     Reads the certificate
                                         Compares issuer against:
 Response 200? → forward proxy           ├── Let's Encrypt, DigiCert  → legitimate
 Response 407? → proxy with auth         └── Fortinet, Zscaler        → intercepted
 No response?  → no proxy
```

**DNSProbe** — compares resolutions to detect manipulation:

```
                     ┌──── System resolver  ────► "1.2.3.4"
 "resolve domain" ───┤                                        equal? → OK
                     └──── Google 8.8.8.8  ────► "1.2.3.4"   differ? → DNS manipulated

 Also resolves a non-existent domain:
   response with IP? → NXDOMAIN hijacking (ISP redirects fake domains)
   NXDOMAIN error?   → clean DNS
```

**DPIProbe** — the most revealing test. Connects to port 443 (open) and sends an SSH banner:

```
 sock.connect((target, 443))
 sock.sendall("SSH-2.0-OpenSSH_8.9\r\n")
     │
     ├── connection dies with RST  → DPI detects SSH on non-SSH port
     └── normal response           → no protocol inspection
```

If the firewall sees `SSH-2.0` on a port that should be HTTPS and kills the connection, we know there's active DPI. This completely changes the technique ranking.

### Phase 2 — Decision: "which technique to use?"

The scoring engine receives results from all 5 probes and scores 8 techniques. Each one is evaluated across 6 dimensions with different weights (most important weighs more):

```
 channel_available  (weight 3.0)  →  Is there an open transport channel?
 dpi_resistance     (weight 2.5)  →  Does it resist the detected deep inspection?
 bandwidth          (weight 1.5)  →  Estimated bandwidth
 latency            (weight 1.0)  →  Connection delay
 setup_complexity   (weight 1.0)  →  Ease of deployment
 stealth            (weight 1.0)  →  How "normal" the traffic looks to an observer
```

Each dimension receives a value between 0.0 and 1.0 multiplied by its weight. The result is a score from 0 to 10. Example with DPI detected and port 443 open:

```
              channel  dpi_resist  bw    latency  setup  stealth  SCORE
 obfs4proxy    1.0      0.95      0.85    0.8     0.5    0.95     8.9
 WebSocket     1.0      0.80      0.90    0.85    0.65   0.85     8.4
 Stunnel       1.0      0.70      0.95    0.90    0.70   0.70     8.2
 DNS Tunnel    1.0      0.70      0.15    0.30    0.40   0.60     6.3
 Direct SSH    BLOCKED  ──────────────────────────────────────     ---
```

obfs4 wins because it's designed for DPI (0.95 in `dpi_resistance`), while Stunnel drops because DPI can detect SSH patterns within TLS.

### Phase 3 — Configuration: "give me the ready files"

For the winning technique, real configuration files are generated (not generic templates). They include the target IP, domain, user, and correct SSH ProxyCommand:

```
 output/
 ├── ssh_config              ← Entry for ~/.ssh/config with ProxyCommand
 ├── wstunnel-server.sh      ← Command to start the server
 ├── wstunnel-client.sh      ← Command to start the client
 ├── nginx-wstunnel.conf     ← Nginx config as reverse proxy + decoy website
 └── docker-compose.yml      ← (with --docker) Full deployable stack
```

---

## Prerequisites

- **Docker** and **Docker Compose** (v2)
- Nothing else. All dependencies (Python 3.12, scapy, requests, pytest, iputils, tcpdump, dnsutils) are installed inside the Docker image.

---

## Installation

```bash
# 1. Clone or download the project
cd covert-ssh-scanner

# 2. Build the images (once)
docker compose build

# 3. Verify it works
docker compose run --rm tests
```

The image is based on `python:3.12-slim` and weighs approximately 250 MB.

### Available Docker services

The `docker-compose.yml` file defines three services:

| Service | Purpose | Exposed port |
|---|---|---|
| `scanner` | Interactive container to run any command | None (uses `network_mode: host`) |
| `stego-srv` | Steganographic HTTP server (persistent PoC) | **9080** |
| `tests` | Runs the 36-test suite and exits | None |

The `scanner` service uses `network_mode: host` for direct access to the host network, required for TCP/DNS/ICMP probes to work against real targets. It also has `NET_RAW` and `NET_ADMIN` capabilities for ICMP probes and packet capture.

Generated configurations persist in `./output/` via a Docker volume.

---

## Usage guide

### 1. First scan (simulation mode)

The `--simulate` mode makes no real connections. It uses example data to show what a complete scan looks like. Ideal for understanding the tool before targeting a real host.

```bash
docker compose run --rm scanner scan --target 203.0.113.50 --domain covert.example.com --simulate
```

**Expected output:**

```
━━━ Network Probes ━━━
  TCP/22    : ✗ Filtered   (timeout)
  TCP/53    : ✓ Open       (DNS) [12ms]
  TCP/80    : ✓ Open       (HTTP/1.1 200 OK) [15ms]
  TCP/443   : ✓ Open       (HTTPS) [19ms]
  ...

━━━ Advanced Detection ━━━
  HTTP Proxy    : ✓ No proxy detected
  TLS Intercept : ✓ Certificate chain valid (Let's Encrypt)
  DPI Active    : ⚠ SSH banner on :443 was RST (probable DPI)
  DNS Filtering : ✓ No DNS manipulation detected

━━━ Recommended Techniques (ranked) ━━━
  #1   obfs4proxy       [Score: 8.9/10]  DPI detected → obfuscation needed
  #2   Shadowsocks      [Score: 8.5/10]  Port 443 available, AEAD evasion
  #3   WebSocket/TLS    [Score: 8.4/10]  Port 443 open, hard to fingerprint
  #4   Stunnel+SSLH     [Score: 8.2/10]  TLS wrapping viable
  #5   DNS Tunnel       [Score: 6.3/10]  DNS open, ~80 Kbps
  #6   Tor Hidden Svc   [Score: 5.4/10]  DPI may block Tor
  ✗   Direct SSH       [Blocked]        Port 22 filtered
  ✗   ICMP Tunnel      [N/A]            Requires root
```

There's also `--dry-run` which shows what probes would run without doing anything:

```bash
docker compose run --rm scanner scan --target 203.0.113.50 --dry-run
```

### 2. Real scan against a target

**Basic scan** (no root — TCP, HTTP, DNS, DPI):

```bash
docker compose run --rm scanner scan \
  --target 198.51.100.10 \
  --domain my-server.com
```

**Full scan** (with root — adds ICMP):

```bash
docker compose run --rm scanner scan \
  --target 198.51.100.10 \
  --domain my-server.com \
  --full
```

The `--full` flag activates the ICMP probe which requires raw sockets. The Docker container already has the `NET_RAW` capability, no extra configuration needed.

**Useful options:**

| Flag | Effect |
|---|---|
| `--target IP` | IP or hostname of the destination SSH server (required) |
| `--domain FQDN` | Domain for TLS/DNS checks (defaults to target) |
| `--full` | Include probes that require root (ICMP) |
| `--timeout N` | Timeout per probe in seconds (default: 5) |
| `--simulate` | Simulated data, no network access |
| `--dry-run` | Show what it would do without executing |
| `--user NAME` | SSH user for generated configs (default: root) |
| `--output DIR` | Output directory (default: `./output/`) |
| `--no-generate` | Don't auto-generate configs |

### 3. Generate configurations

If you already know which technique you want, or want the tool to choose automatically:

```bash
# Auto-detect best technique (runs a quick scan first)
docker compose run --rm scanner generate \
  --target 198.51.100.10 \
  --technique auto \
  --user operator

# Specific technique
docker compose run --rm scanner generate \
  --target 198.51.100.10 \
  --technique websocket \
  --domain my-server.com \
  --user operator

# Add docker-compose.yml for deployment
docker compose run --rm scanner generate \
  --target 198.51.100.10 \
  --technique stunnel \
  --docker
```

**Available techniques:** `stunnel`, `sslh`, `websocket` (`ws`, `wstunnel`), `obfs4`, `dns`, `icmp`, `tor`, `shadowsocks` (`ss`), `direct`, `auto`.

**Generated files** (example for `websocket`):

```
output/
├── ssh_config              # Entry for ~/.ssh/config with ProxyCommand
├── wstunnel-server.sh      # Command to start the wstunnel server
├── wstunnel-client.sh      # Command to start the wstunnel client
├── nginx-wstunnel.conf     # Nginx config as reverse proxy with decoy website
└── docker-compose.yml      # (if --docker was used) Full deployable stack
```

### 4. Steganography module

The `stego` module is a proof-of-concept that hides SSH traffic inside HTTP requests that look like legitimate web browsing. It has four modes:

#### Demo — see encode/decode in action

```bash
docker compose run --rm scanner stego --mode demo
```

Shows how 21 bytes of SSH banner (`SSH-2.0-OpenSSH_8.9\r\n`) are encoded into cookies, query parameters, and JSON bodies, and decoded correctly.

#### HTTP Cover — see what the cover traffic looks like

```bash
docker compose run --rm scanner stego --mode http-cover
```

Generates 3 sample HTTP requests showing how hidden data looks: rotated User-Agent, cookies resembling tracking, JSON resembling telemetry.

#### Server — receive hidden data

```bash
# Start as a service (background)
docker compose up stego-srv -d

# Or manually with custom port
docker compose run --rm -p 9080:9080 scanner stego --mode server --port 9080
```

The server listens for normal HTTP requests. If it detects steganographic data (magic bytes + XOR mask), it decodes them and forwards to local SSH. If the request is normal, it returns a "decoy" JSON page that looks like a real API.

#### Client — send hidden data

```bash
docker compose run --rm scanner stego \
  --mode client \
  --target 198.51.100.10 \
  --port 9080 \
  --key my-secret-key
```

Opens a local proxy on `127.0.0.1:2222`. When connecting SSH to that port, traffic is encoded into HTTP requests and sent to the remote stego server. The `--key` flag defines the shared key for the XOR mask (must be the same on client and server).

---

## Command reference

### General format

```bash
docker compose run --rm scanner <command> [options]
```

### Available commands

| Command | Description |
|---|---|
| `scan` | Scans the network and recommends techniques |
| `generate` | Generates configuration files for a technique |
| `stego` | HTTP steganography module (experimental) |

### scan — full options

```
scan --target IP [--domain FQDN] [--full] [--timeout N]
     [--simulate] [--dry-run] [--user USER] [--output DIR]
     [--no-generate] [--skip-config]
```

### generate — full options

```
generate --target IP --technique TECHNIQUE [--domain FQDN]
         [--user USER] [--output DIR] [--docker] [--simulate]
```

### stego — full options

```
stego --mode {demo,server,client,http-cover}
      [--target IP] [--port N] [--ssh-port N]
      [--local-port N] [--key KEY]
```

---

## Project architecture

```
covert-ssh-scanner/
├── Dockerfile                    # Docker image (python:3.12-slim + deps)
├── docker-compose.yml            # 3 services: scanner, stego-srv, tests
│
├── scanner/                      # Main package
│   ├── __init__.py               # Version and metadata
│   ├── __main__.py               # Enables 'python -m scanner'
│   ├── cli.py                    # CLI interface (argparse + colored output)
│   │
│   ├── probes/                   # PHASE 1: Reconnaissance probes
│   │   ├── tcp_probe.py          #   TCP port scan + banner grabbing
│   │   ├── http_probe.py         #   HTTP proxy detection + TLS interception
│   │   ├── dns_probe.py          #   DNS analysis (manipulation, NXDOMAIN hijack)
│   │   ├── icmp_probe.py         #   ICMP echo with variable payloads (root)
│   │   └── dpi_probe.py          #   DPI: SSH banner on :443, SSH-in-TLS, proto enforcement
│   │
│   ├── engine/                   # PHASE 2: Decision engine
│   │   ├── scorer.py             #   Weighted scoring of 8 techniques x 6 criteria
│   │   └── recommender.py        #   Orchestrator: runs probes → scorer → ranking
│   │
│   ├── generators/               # PHASE 3: Configuration generation
│   │   ├── stunnel.py            #   Stunnel config (server/client/SSLH/docker-compose)
│   │   ├── wstunnel.py           #   wstunnel config + nginx reverse proxy
│   │   ├── sslh.py               #   SSLH multiplexer config
│   │   ├── tor.py                #   Tor Hidden Service config
│   │   └── ssh_config.py         #   ~/.ssh/config entries for all 8 techniques
│   │
│   └── stego/                    # BONUS: HTTP steganography
│       └── http_stego.py         #   Encoder/Decoder + HTTP stego server/client
│
└── tests/
    └── test_probes.py            # 36 unit tests (simulation + scoring + stego)
```

### Internal data flow

```
cli.py → Recommender.assess()
              │
              ├── TCPProbe.run()    → TCPProbeResult
              ├── HTTPProbe.run()   → HTTPProbeResult
              ├── DNSProbe.run()    → DNSProbeResult
              ├── ICMPProbe.run()   → ICMPProbeResult  (only with --full)
              └── DPIProbe.run()    → DPIProbeResult
                      │
                      ▼
              TechniqueScorer.score_all(probes)
                      │
                      ▼
              List[TechniqueScore]  (8 techniques ranked)
                      │
                      ▼
              *Generator.generate() (configuration files)
```

---

## How the decision engine works

### Scoring criteria

Each technique is evaluated across 6 dimensions with configurable weights:

| Criterion | Weight | What it measures |
|---|---|---|
| `channel_available` | 3.0 | Is there an open transport channel? (TCP port, DNS, ICMP...) |
| `dpi_resistance` | 2.5 | Resistance to detected deep packet inspection |
| `bandwidth` | 1.5 | Estimated channel bandwidth |
| `latency` | 1.0 | Connection latency |
| `setup_complexity` | 1.0 | Ease of deployment (inverted: simpler = more points) |
| `stealth` | 1.0 | How "normal" the traffic looks to an observer |

### Evaluated techniques

| Technique | Shines when | Fails when |
|---|---|---|
| **Direct SSH** | Port 22 open, no DPI | Almost always blocked |
| **Stunnel+SSLH** | Port 443 open, no TLS interception | DPI detects SSH within TLS |
| **WebSocket/TLS** | Port 443 open, WebSocket traffic not inspected | Proxy doesn't support WebSocket |
| **obfs4proxy** | Active DPI, strong obfuscation needed | High setup complexity |
| **DNS Tunnel** | Only DNS available, everything else blocked | Bandwidth ~50-150 Kbps |
| **ICMP Tunnel** | Only ping available | Very slow, requires root on both sides |
| **Tor Hidden Svc** | Anonymity needed, outbound connectivity | Latency >500ms, Tor may be blocked |
| **Shadowsocks** | Active DPI, good bandwidth needed | Moderate setup |

### Scoring logic example

Scenario: port 22 filtered, port 443 open, DPI detects SSH on :443, clean DNS.

```
 What the scorer sees:
   tcp.ports[22].state  = "filtered"   → Direct SSH blocked
   tcp.ports[443].state = "open"       → Stunnel/WS/obfs4/SS possible
   dpi.ssh_banner_blocked = True       → penalize techniques without obfuscation
   dns.tunnel_viable = True            → DNS tunnel available but slow
   icmp = None                         → not tested (no --full)
```

Ranking consequences:

1. **obfs4proxy** (8.9) — DPI detected, but obfs4 generates bytes indistinguishable from random noise. Scores 0.95 in `dpi_resistance`.
2. **Stunnel+SSLH** (8.2) — Port 443 open, but DPI could detect SSH patterns within TLS. Drops to 0.70 in `dpi_resistance`.
3. **DNS Tunnel** (6.3) — DNS works and DPI doesn't affect it, but only ~80 Kbps. Scores 0.15 in `bandwidth`.
4. **Direct SSH** (Blocked) — Port 22 filtered, not even evaluated.

---

## Steganography module in detail

### Concept

The `stego` module hides SSH data inside HTTP requests that look like legitimate web traffic. The encoding chain:

```
 Real SSH data:  b"SSH-2.0-OpenSSH_8.9\r\n"  (21 bytes)
        │
        ▼  XOR with SHA-256(shared key)
 obfuscated bytes ("SSH" is nowhere to be seen)
        │
        ▼  prepend magic bytes + sequence number
 \xDE\xAD  +  \x00\x03  +  <masked_data>
        │
        ▼  base64 encode
 "3q0AA8ZpJxf5Or9QS-LM8Iad0IJ8DR_7SQ"
        │
        ▼  spread across HTTP channels
 ┌───────────────────────────────────────────────────────────────┐
 │  GET /api/v2/analytics/collect?utm_source=3q0AA8...           │
 │  Cookie: _ga=3q0AA8Z; _gid=pJxf5Or; session_id=QS-LM8...    │
 │  User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 17_2...)      │
 └───────────────────────────────────────────────────────────────┘
        │
        ▼  To a network observer, this looks like:
        "an iPhone visiting an analytics API"
```

The server reverses the process: it looks for the magic bytes `\xDE\xAD` in cookies/query/body, undoes the base64, undoes the XOR, and obtains the original SSH bytes. If the request contains no magic bytes, it returns a "decoy" JSON page that looks like a real API.

Data is spread across three channels depending on size:

| Channel | Where data is hidden | Appearance to an observer |
|---|---|---|
| **Cookies** | Cookie values (`_ga`, `_gid`, `session_id`...) | Normal tracking/analytics cookies |
| **Query params** | UTM parameters (`utm_source`, `utm_campaign`, `cd1`) | Google Analytics / marketing tags |
| **JSON body** | `data` field inside a "telemetry" JSON | Analytics/event API call |

### Anti-analysis techniques

- **User-Agent rotation**: 5 real browsers (Chrome, Safari, Firefox, Linux, iPhone)
- **Random paths**: `/api/v2/analytics/collect`, `/cdn/assets/config.json`...
- **Temporal jitter**: 50-200ms random delay between requests
- **XOR mask**: Data is masked with SHA-256 of the shared key
- **Magic bytes**: `\xDE\xAD` + sequence number to identify stego packets vs real traffic

### Limitations (it's a PoC)

- XOR is not real encryption (just obfuscation)
- No flow control or packet reordering
- Overhead is ~1.9x (512 bytes of data → ~962 bytes HTTP)
- Does not withstand advanced statistical traffic analysis

---

## Tests

```bash
docker compose run --rm tests
```

### What the 36 tests cover

| Group | Tests | What it validates |
|---|---|---|
| `TestTCPProbe` | 3 | TCP simulation returns correct ports |
| `TestHTTPProbe` | 2 | HTTP/TLS simulation correct |
| `TestDNSProbe` | 2 | DNS simulation + tunnel viability |
| `TestICMPProbe` | 2 | ICMP simulation + latency |
| `TestDPIProbe` | 2 | DPI simulation + test results |
| `TestScorer` | 6 | Correct scoring, sorting, SSH blocked, obfs4 high with DPI |
| `TestRecommender` | 3 | Full pipeline, dry-run, viable technique |
| `TestGenerators` | 7 | All configs generate correctly |
| `TestSteganography` | 9 | JSON round-trip, cookies, large payloads, wrong key fails |

All tests use `simulate` mode and require no network access.

---

## FAQ

### How does the tool decide which technique to recommend?

Each probe collects facts about the network (port open/closed, active DPI, manipulated DNS...). With those facts, the scoring engine evaluates 8 techniques across 6 weighted dimensions:

```
 channel_available  (weight 3.0)  →  Is there an open transport channel?
 dpi_resistance     (weight 2.5)  →  Does it resist the detected deep inspection?
 bandwidth          (weight 1.5)  →  Estimated bandwidth
 latency            (weight 1.0)  →  Connection delay
 setup_complexity   (weight 1.0)  →  Ease of deployment
 stealth            (weight 1.0)  →  How "normal" the traffic looks
```

Each dimension receives a value between 0.0 and 1.0 multiplied by its weight. The result is a score from 0 to 10. The technique with the highest score is recommended.

### Why isn't an open port enough to tunnel SSH?

Because many firewalls have **Deep Packet Inspection (DPI)**: they allow connections to port 443 but inspect the first bytes. If they see `SSH-2.0-...` instead of a TLS ClientHello, they kill the connection with a RST.

The DPI probe detects exactly this: it connects to port 443 and sends an SSH banner. If the connection dies, the scorer penalizes techniques like Stunnel (which wraps SSH in TLS but with detectable patterns) and favors obfs4 (which generates bytes indistinguishable from random noise).

### How does the steganography module work?

It transforms SSH bytes into HTTP requests that look like web browsing traffic:

```
 SSH bytes  →  XOR with SHA-256(key)  →  base64  →  spread into:
                                                     ├── cookies (_ga, _gid, session_id)
                                                     ├── query params (utm_source, utm_campaign)
                                                     └── JSON body ("telemetry" API)
```

To a network observer, the traffic looks like a browser visiting an analytics API. The server looks for the magic bytes `\xDE\xAD` in requests to distinguish stego from real traffic, and reverses the process to obtain the original SSH bytes.

### Is the stego module safe for real-world use?

No. It's an academic proof-of-concept. The XOR mask is not encryption, there's no authentication, and the traffic pattern wouldn't withstand serious statistical analysis. For real-world use, use the techniques recommended by the scanner (obfs4, wstunnel, etc.).

### Do I need root on the host?

No. Docker handles permissions. The container already has `NET_RAW` and `NET_ADMIN` capabilities configured in `docker-compose.yml`, so the `--full` flag (ICMP probes) works out of the box.

### What if port 9080 is busy?

Edit `docker-compose.yml` and change `"9080:9080"` to another free port, for example `"9090:9090"`. Remember to also change the `--port` flag in the `stego-srv` service command.

### Can I add my own evasion techniques?

Yes. Add a new `TechniqueID` in `scanner/engine/scorer.py`, create the `_score_my_technique()` method in `TechniqueScorer`, and optionally a generator in `scanner/generators/`.

---

## License

MIT — See [LICENSE](LICENSE) file.
