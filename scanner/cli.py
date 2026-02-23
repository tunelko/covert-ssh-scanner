"""Command-line interface for Covert SSH Scanner.

Provides scan, generate, and stego subcommands with colored terminal output.
"""

import argparse
import os
import sys
import time
from pathlib import Path

from scanner import __version__
from scanner.engine.recommender import Recommender, NetworkAssessment
from scanner.engine.scorer import TechniqueID, TechniqueScore
from scanner.generators.stunnel import StunnelGenerator
from scanner.generators.wstunnel import WstunnelGenerator
from scanner.generators.sslh import SSLHGenerator
from scanner.generators.tor import TorGenerator
from scanner.generators.ssh_config import SSHConfigGenerator


# ─── ANSI Color Codes ─────────────────────────────────────────────────────────

class C:
    """ANSI color codes for terminal output."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"

    BG_BLUE = "\033[44m"
    BG_RED = "\033[41m"

    @classmethod
    def disable(cls):
        """Disable colors (for non-TTY output)."""
        for attr in dir(cls):
            if attr.isupper() and not attr.startswith("_"):
                setattr(cls, attr, "")


# Disable colors if not a TTY
if not sys.stdout.isatty():
    C.disable()


# ─── Banner ───────────────────────────────────────────────────────────────────

BANNER = f"""\
{C.CYAN}{C.BOLD}
   ██████╗ ██████╗ ██╗   ██╗███████╗██████╗ ████████╗
  ██╔════╝██╔═══██╗██║   ██║██╔════╝██╔══██╗╚══██╔══╝
  ██║     ██║   ██║██║   ██║█████╗  ██████╔╝   ██║
  ██║     ██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗   ██║
  ╚██████╗╚██████╔╝ ╚████╔╝ ███████╗██║  ██║   ██║
   ╚═════╝ ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝   ╚═╝
{C.RESET}{C.MAGENTA}
     ███████╗███████╗██╗  ██╗
     ██╔════╝██╔════╝██║  ██║
     ███████╗███████╗███████║
     ╚════██║╚════██║██╔══██║
     ███████║███████║██║  ██║
     ╚══════╝╚══════╝╚═╝  ╚═╝
{C.RESET}{C.YELLOW}
  ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
  ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
  ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
  ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
  ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
{C.RESET}
  {C.DIM}Covert SSH Channel Scanner v{__version__}{C.RESET}
  {C.DIM}Author: tunelko{C.RESET}
"""


# ─── Output Formatting ────────────────────────────────────────────────────────

def print_header(text: str):
    """Print a boxed header."""
    width = 56
    print(f"\n{C.CYAN}{'═' * width}")
    print(f"  {C.BOLD}{text}{C.RESET}{C.CYAN}")
    print(f"{'═' * width}{C.RESET}")


def print_section(text: str):
    """Print a section header."""
    print(f"\n{C.BOLD}━━━ {text} ━━━{C.RESET}")


def status_icon(state: str) -> str:
    """Return colored status icon."""
    icons = {
        "open": f"{C.GREEN}✓{C.RESET}",
        "closed": f"{C.RED}✗{C.RESET}",
        "filtered": f"{C.RED}✗{C.RESET}",
        "warning": f"{C.YELLOW}⚠{C.RESET}",
        "ok": f"{C.GREEN}✓{C.RESET}",
        "blocked": f"{C.RED}✗{C.RESET}",
        "na": f"{C.RED}✗{C.RESET}",
    }
    return icons.get(state, "?")


# ─── Scan Command ─────────────────────────────────────────────────────────────

def cmd_scan(args):
    """Execute network scan and display results."""
    print(BANNER)
    print_header("Covert SSH Scanner — Network Assessment")

    recommender = Recommender(
        target=args.target,
        domain=args.domain,
        timeout=args.timeout,
        full_scan=args.full,
    )

    print(f"\n  {C.BOLD}[*]{C.RESET} Target: {C.CYAN}{args.target}{C.RESET}", end="")
    if args.domain and args.domain != args.target:
        print(f" ({C.CYAN}{args.domain}{C.RESET})", end="")
    print()

    if args.dry_run:
        print(f"  {C.BOLD}[*]{C.RESET} Mode: {C.YELLOW}DRY RUN{C.RESET}")
    elif args.simulate:
        print(f"  {C.BOLD}[*]{C.RESET} Mode: {C.YELLOW}SIMULATE{C.RESET}")

    print(f"  {C.BOLD}[*]{C.RESET} Scanning...\n")

    start = time.monotonic()
    assessment = recommender.assess(
        simulate=args.simulate,
        dry_run=args.dry_run,
    )
    elapsed = time.monotonic() - start

    if args.dry_run:
        print_section("Dry Run — Planned Probes")
        for error in assessment.errors:
            print(f"  {C.DIM}{error}{C.RESET}")
        print(f"\n  {C.DIM}Elapsed: {elapsed:.1f}s{C.RESET}")
        return

    # Display source IP
    if assessment.source_ip:
        print(f"  {C.BOLD}[*]{C.RESET} Scanning from: {assessment.source_ip}")

    # ── TCP Results ──
    if assessment.tcp:
        print_section("Network Probes")
        for port, result in sorted(assessment.tcp.ports.items()):
            icon = status_icon(result.state)
            proto = result.service or f"TCP/{port}"
            detail = ""
            if result.state == "open":
                if result.banner:
                    detail = f"({result.banner[:40]})"
                elif result.service:
                    detail = f"({result.service})"
                if result.latency_ms:
                    detail += f" [{result.latency_ms:.0f}ms]"
            elif result.state == "filtered":
                detail = "(timeout)"
            elif result.state == "closed":
                detail = "(RST)"

            label = f"TCP/{port}".ljust(10)
            print(f"  {label}: {icon} {result.state.capitalize():10s} {detail}")

    # ── DNS Results ──
    if assessment.dns:
        dns = assessment.dns
        icon = status_icon("ok" if dns.dns_open else "blocked")
        bw = f", ~{dns.estimated_bandwidth_kbps:.0f}Kbps" if dns.tunnel_viable else ""
        print(f"  {'UDP/53':10s}: {icon} {'Open' if dns.dns_open else 'Blocked':10s} "
              f"({dns.details[:50]}{bw})")

    # ── ICMP Results ──
    if assessment.icmp:
        icmp = assessment.icmp
        if icmp.requires_root:
            print(f"  {'ICMP':10s}: {status_icon('na')} {'N/A':10s} (requires root)")
        elif icmp.icmp_allowed:
            restrict = "no size restriction" if not icmp.size_restricted else "size restricted"
            print(f"  {'ICMP':10s}: {status_icon('ok')} {'Allowed':10s} "
                  f"(avg {icmp.avg_latency_ms:.0f}ms, {restrict})")
        else:
            print(f"  {'ICMP':10s}: {status_icon('blocked')} {'Blocked':10s}")

    # ── Advanced Detection ──
    print_section("Advanced Detection")

    if assessment.http:
        http = assessment.http
        if http.proxy_detected:
            print(f"  HTTP Proxy    : {status_icon('warning')} "
                  f"{http.proxy_type} — {http.proxy_details}")
        else:
            print(f"  HTTP Proxy    : {status_icon('ok')} No proxy detected")

        if http.tls_intercept:
            print(f"  TLS Intercept : {status_icon('warning')} "
                  f"{http.tls_details}")
        else:
            issuer_info = f" ({http.tls_issuer})" if http.tls_issuer else ""
            print(f"  TLS Intercept : {status_icon('ok')} "
                  f"Certificate chain valid{issuer_info}")

    if assessment.dpi:
        dpi = assessment.dpi
        if dpi.dpi_detected:
            print(f"  DPI Active    : {status_icon('warning')} {dpi.details}")
        else:
            print(f"  DPI Active    : {status_icon('ok')} No DPI indicators found")

    if assessment.dns:
        dns = assessment.dns
        if dns.dns_manipulated:
            print(f"  DNS Filtering : {status_icon('warning')} {dns.details}")
        else:
            print(f"  DNS Filtering : {status_icon('ok')} "
                  f"No DNS manipulation detected")

    # ── Recommendations ──
    if assessment.scores:
        print_section("Recommended Techniques (ranked)")
        rank = 1
        for score in assessment.scores:
            if score.blocked:
                print(f"  {C.RED}✗{C.RESET}   {score.name:16s} "
                      f"[{C.RED}{score.display_score}{C.RESET}]"
                      f"        {C.DIM}{score.justification}{C.RESET}")
            elif score.not_tested:
                print(f"  {C.RED}✗{C.RESET}   {score.name:16s} "
                      f"[{C.YELLOW}N/A{C.RESET}]"
                      f"            {C.DIM}{score.justification}{C.RESET}")
            else:
                color = C.GREEN if score.score >= 7 else (
                    C.YELLOW if score.score >= 5 else C.RED
                )
                print(f"  #{rank:<3d} {C.BOLD}{score.name:16s}{C.RESET} "
                      f"[{color}Score: {score.display_score}{C.RESET}]  "
                      f"{score.justification}")
                rank += 1

    # ── Auto-generate config for best technique ──
    if assessment.best_technique and not args.no_generate:
        best = assessment.best_technique
        print(f"\n  {C.BOLD}[*]{C.RESET} Best technique: "
              f"{C.GREEN}{C.BOLD}{best.name}{C.RESET}")

        if not args.skip_config:
            output_dir = Path(args.output) if args.output else Path("./output")
            _generate_config(
                args.target, args.domain, best.technique,
                args.user, output_dir
            )

    print(f"\n  {C.DIM}Scan completed in {elapsed:.1f}s{C.RESET}\n")


# ─── Generate Command ─────────────────────────────────────────────────────────

TECHNIQUE_MAP = {
    "stunnel": TechniqueID.STUNNEL_SSLH,
    "stunnel_sslh": TechniqueID.STUNNEL_SSLH,
    "sslh": TechniqueID.STUNNEL_SSLH,
    "websocket": TechniqueID.WEBSOCKET_TLS,
    "wstunnel": TechniqueID.WEBSOCKET_TLS,
    "ws": TechniqueID.WEBSOCKET_TLS,
    "obfs4": TechniqueID.OBFS4,
    "obfs4proxy": TechniqueID.OBFS4,
    "dns": TechniqueID.DNS_TUNNEL,
    "dns_tunnel": TechniqueID.DNS_TUNNEL,
    "icmp": TechniqueID.ICMP_TUNNEL,
    "icmp_tunnel": TechniqueID.ICMP_TUNNEL,
    "tor": TechniqueID.TOR,
    "shadowsocks": TechniqueID.SHADOWSOCKS,
    "ss": TechniqueID.SHADOWSOCKS,
    "direct": TechniqueID.DIRECT_SSH,
}


def cmd_generate(args):
    """Generate configuration files for a specific technique."""
    print(BANNER)
    print_header("Configuration Generator")

    technique_key = args.technique.lower().replace("-", "_")

    if technique_key == "auto":
        # Run a quick scan to determine best technique
        print(f"\n  {C.BOLD}[*]{C.RESET} Auto-detecting best technique...")
        recommender = Recommender(
            target=args.target,
            domain=args.domain,
            timeout=args.timeout,
        )
        assessment = recommender.assess(simulate=args.simulate)
        if assessment.best_technique:
            technique_id = assessment.best_technique.technique
            print(f"  {C.BOLD}[*]{C.RESET} Selected: "
                  f"{C.GREEN}{assessment.best_technique.name}{C.RESET}")
        else:
            print(f"  {C.RED}[!] No viable technique found{C.RESET}")
            sys.exit(1)
    elif technique_key in TECHNIQUE_MAP:
        technique_id = TECHNIQUE_MAP[technique_key]
    else:
        print(f"  {C.RED}[!] Unknown technique: {args.technique}{C.RESET}")
        print(f"  Available: {', '.join(sorted(TECHNIQUE_MAP.keys()))}")
        sys.exit(1)

    output_dir = Path(args.output) if args.output else Path("./output")
    _generate_config(args.target, args.domain, technique_id,
                     args.user, output_dir, docker=args.docker)


def _generate_config(target: str, domain: str | None, technique: TechniqueID,
                     user: str, output_dir: Path, docker: bool = False):
    """Generate and write configuration files."""
    output_dir.mkdir(parents=True, exist_ok=True)
    domain = domain or target
    files_written = []

    print(f"\n  {C.BOLD}[*]{C.RESET} Generating config for: "
          f"{C.CYAN}{technique.value}{C.RESET}")

    # SSH config (always generated)
    ssh_gen = SSHConfigGenerator(target, domain, user)
    ssh_config = ssh_gen.generate(technique)
    ssh_path = output_dir / "ssh_config"
    ssh_path.write_text(ssh_config.config_entry)
    files_written.append(str(ssh_path))

    # Technique-specific configs
    if technique == TechniqueID.STUNNEL_SSLH:
        gen = StunnelGenerator(target, user=user)
        config = gen.generate()
        (output_dir / "stunnel-server.conf").write_text(config.server_conf)
        (output_dir / "stunnel-client.conf").write_text(config.client_conf)
        files_written.extend([
            str(output_dir / "stunnel-server.conf"),
            str(output_dir / "stunnel-client.conf"),
        ])

        sslh_conf = gen.generate_sslh_config()
        (output_dir / "sslh.conf").write_text(sslh_conf)
        files_written.append(str(output_dir / "sslh.conf"))

        if docker:
            (output_dir / "docker-compose.yml").write_text(
                gen.generate_docker_compose()
            )
            files_written.append(str(output_dir / "docker-compose.yml"))

        print(f"  {C.DIM}SSH command:{C.RESET} {config.ssh_command}")

    elif technique == TechniqueID.WEBSOCKET_TLS:
        gen = WstunnelGenerator(target, domain, user=user)
        config = gen.generate()
        (output_dir / "wstunnel-server.sh").write_text(
            f"#!/bin/bash\n{config.server_command}\n"
        )
        (output_dir / "wstunnel-client.sh").write_text(
            f"#!/bin/bash\n{config.client_command}\n"
        )
        (output_dir / "nginx-wstunnel.conf").write_text(config.nginx_conf)
        files_written.extend([
            str(output_dir / "wstunnel-server.sh"),
            str(output_dir / "wstunnel-client.sh"),
            str(output_dir / "nginx-wstunnel.conf"),
        ])

        if docker:
            (output_dir / "docker-compose.yml").write_text(
                gen.generate_docker_compose()
            )
            files_written.append(str(output_dir / "docker-compose.yml"))

        print(f"  {C.DIM}SSH command:{C.RESET} {config.ssh_command}")

    elif technique == TechniqueID.STUNNEL_SSLH:
        gen = SSLHGenerator(target, user=user)
        config = gen.generate()
        (output_dir / "sslh.cfg").write_text(config.config_file)
        (output_dir / "sslh-systemd.conf").write_text(config.systemd_override)
        files_written.extend([
            str(output_dir / "sslh.cfg"),
            str(output_dir / "sslh-systemd.conf"),
        ])
        print(f"  {C.DIM}SSH command:{C.RESET} {config.ssh_command}")

    elif technique == TechniqueID.TOR:
        gen = TorGenerator(target, user=user)
        config = gen.generate()
        (output_dir / "torrc-server").write_text(config.torrc)
        (output_dir / "torrc-client").write_text(config.client_torrc)
        files_written.extend([
            str(output_dir / "torrc-server"),
            str(output_dir / "torrc-client"),
        ])

        if docker:
            (output_dir / "docker-compose.yml").write_text(
                gen.generate_docker_compose()
            )
            files_written.append(str(output_dir / "docker-compose.yml"))

        print(f"  {C.DIM}SSH command:{C.RESET} {config.ssh_command}")

    else:
        print(f"  {C.DIM}SSH command:{C.RESET} {ssh_config.direct_command}")

    # Print description
    print(f"\n  {C.DIM}{ssh_config.description}{C.RESET}")

    # List written files
    print(f"\n  {C.BOLD}[*]{C.RESET} Files written to: {C.CYAN}{output_dir}{C.RESET}")
    for f in files_written:
        print(f"      {C.DIM}{f}{C.RESET}")


# ─── Stego Command ────────────────────────────────────────────────────────────

def cmd_stego(args):
    """Handle steganography subcommand."""
    print(BANNER)
    print_header("HTTP Steganography Module (Experimental)")

    if args.mode == "demo":
        from scanner.stego.http_stego import demo_encode_decode
        demo_encode_decode()

    elif args.mode == "server":
        from scanner.stego.http_stego import HTTPStegoServer, HTTPStegoServer as Handler
        from http.server import HTTPServer

        port = args.port or 8080
        Handler.ssh_host = "127.0.0.1"
        Handler.ssh_port = args.ssh_port or 22

        print(f"\n  {C.BOLD}[*]{C.RESET} Starting stego server on :{port}")
        print(f"  {C.BOLD}[*]{C.RESET} Forwarding to SSH on "
              f"127.0.0.1:{Handler.ssh_port}")
        print(f"  {C.DIM}Press Ctrl+C to stop{C.RESET}\n")

        server = HTTPServer(("0.0.0.0", port), Handler)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print(f"\n  {C.BOLD}[*]{C.RESET} Server stopped")
            server.server_close()

    elif args.mode == "client":
        from scanner.stego.http_stego import HTTPStegoClient

        if not args.target:
            print(f"  {C.RED}[!] --target required for client mode{C.RESET}")
            sys.exit(1)

        url = f"http://{args.target}:{args.port or 8080}"
        client = HTTPStegoClient(url, key=args.key or "default")

        local_port = args.local_port or 2222
        print(f"\n  {C.BOLD}[*]{C.RESET} Starting stego client proxy")
        print(f"  {C.BOLD}[*]{C.RESET} Local: 127.0.0.1:{local_port}")
        print(f"  {C.BOLD}[*]{C.RESET} Remote: {url}")
        print(f"  {C.DIM}Connect: ssh -p {local_port} user@127.0.0.1{C.RESET}\n")

        try:
            client.start_proxy(local_port)
        except KeyboardInterrupt:
            print(f"\n  {C.BOLD}[*]{C.RESET} Client stopped")
            client.stop()

    elif args.mode == "http-cover":
        # Show what HTTP stego traffic looks like
        from scanner.stego.http_stego import StegoEncoder
        import json

        encoder = StegoEncoder(args.key or "default")
        test_data = b"SSH-2.0-OpenSSH_8.9\r\n"

        print(f"\n  {C.BOLD}HTTP Cover Traffic Demo{C.RESET}\n")
        print(f"  Hiding {len(test_data)} bytes of SSH data in HTTP requests:\n")

        for i in range(3):
            req = encoder.build_request(test_data)
            print(f"  {C.CYAN}--- Request {i+1} ---{C.RESET}")
            print(f"  {req['method']} {req['path'][:70]}...")
            for k, v in req["headers"].items():
                if k in ("Cookie", "User-Agent", "Content-Type"):
                    print(f"  {k}: {v[:70]}{'...' if len(v) > 70 else ''}")
            if req["body"]:
                try:
                    pretty = json.dumps(json.loads(req["body"]), indent=2)
                    for line in pretty.split("\n")[:8]:
                        print(f"  {C.DIM}{line}{C.RESET}")
                    print(f"  {C.DIM}  ...{C.RESET}")
                except json.JSONDecodeError:
                    print(f"  {C.DIM}{req['body'][:100]}...{C.RESET}")
            print()

    else:
        print(f"  {C.RED}[!] Unknown mode: {args.mode}{C.RESET}")
        print(f"  Available: demo, server, client, http-cover")
        sys.exit(1)


# ─── Argument Parser ──────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="covert-ssh-scanner",
        description="Intelligent covert SSH channel scanner and recommender",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m scanner scan --target 203.0.113.50 --domain covert.example.com\n"
            "  sudo python -m scanner scan --target 203.0.113.50 --full\n"
            "  python -m scanner scan --target 203.0.113.50 --simulate\n"
            "  python -m scanner generate --target 203.0.113.50 --technique auto\n"
            "  python -m scanner stego --mode demo\n"
        ),
    )
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # ── scan ──
    scan_parser = subparsers.add_parser(
        "scan", help="Scan target network and recommend techniques"
    )
    scan_parser.add_argument(
        "--target", "-t", required=True,
        help="Target IP address or hostname"
    )
    scan_parser.add_argument(
        "--domain", "-d",
        help="Domain name for TLS/DNS checks (defaults to target)"
    )
    scan_parser.add_argument(
        "--full", "-f", action="store_true",
        help="Full scan including ICMP and DPI (requires root)"
    )
    scan_parser.add_argument(
        "--timeout", type=float, default=5.0,
        help="Probe timeout in seconds (default: 5)"
    )
    scan_parser.add_argument(
        "--simulate", "-s", action="store_true",
        help="Use simulated data (for demo/testing)"
    )
    scan_parser.add_argument(
        "--dry-run", action="store_true",
        help="Show what probes would run without executing"
    )
    scan_parser.add_argument(
        "--output", "-o",
        help="Output directory for generated configs (default: ./output)"
    )
    scan_parser.add_argument(
        "--user", "-u", default="root",
        help="SSH username for generated configs (default: root)"
    )
    scan_parser.add_argument(
        "--no-generate", action="store_true",
        help="Don't auto-generate config for best technique"
    )
    scan_parser.add_argument(
        "--skip-config", action="store_true",
        help="Skip config file generation"
    )

    # ── generate ──
    gen_parser = subparsers.add_parser(
        "generate", help="Generate configuration for a specific technique"
    )
    gen_parser.add_argument(
        "--target", "-t", required=True,
        help="Target IP address or hostname"
    )
    gen_parser.add_argument(
        "--domain", "-d",
        help="Domain name (defaults to target)"
    )
    gen_parser.add_argument(
        "--technique", required=True,
        help=("Technique to configure: auto, stunnel, websocket, obfs4, "
              "dns, icmp, tor, shadowsocks, direct")
    )
    gen_parser.add_argument(
        "--user", "-u", default="root",
        help="SSH username (default: root)"
    )
    gen_parser.add_argument(
        "--output", "-o",
        help="Output directory (default: ./output)"
    )
    gen_parser.add_argument(
        "--docker", action="store_true",
        help="Also generate docker-compose.yml"
    )
    gen_parser.add_argument(
        "--simulate", "-s", action="store_true",
        help="Use simulated scan for auto technique selection"
    )
    gen_parser.add_argument(
        "--timeout", type=float, default=5.0,
        help="Probe timeout for auto mode (default: 5)"
    )

    # ── stego ──
    stego_parser = subparsers.add_parser(
        "stego", help="HTTP steganography module (experimental)"
    )
    stego_parser.add_argument(
        "--mode", "-m", required=True,
        choices=["demo", "server", "client", "http-cover"],
        help="Stego mode: demo, server, client, http-cover"
    )
    stego_parser.add_argument(
        "--target", "-t",
        help="Target server address (for client mode)"
    )
    stego_parser.add_argument(
        "--port", "-p", type=int,
        help="Server listen port or remote port (default: 8080)"
    )
    stego_parser.add_argument(
        "--ssh-port", type=int, default=22,
        help="Local SSH port to forward to (server mode, default: 22)"
    )
    stego_parser.add_argument(
        "--local-port", type=int, default=2222,
        help="Local proxy listen port (client mode, default: 2222)"
    )
    stego_parser.add_argument(
        "--key", "-k", default="default",
        help="Shared secret key for encoding (default: 'default')"
    )

    return parser


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        print(BANNER)
        parser.print_help()
        sys.exit(0)

    commands = {
        "scan": cmd_scan,
        "generate": cmd_generate,
        "stego": cmd_stego,
    }

    cmd_func = commands.get(args.command)
    if cmd_func:
        try:
            cmd_func(args)
        except KeyboardInterrupt:
            print(f"\n{C.YELLOW}[!] Interrupted{C.RESET}")
            sys.exit(130)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
