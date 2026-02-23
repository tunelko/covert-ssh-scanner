"""Technique scoring engine.

Evaluates each covert SSH technique based on network probe results and
assigns a weighted score considering channel availability, DPI resistance,
bandwidth, latency, and setup complexity.
"""

from dataclasses import dataclass, field
from enum import Enum


class TechniqueID(str, Enum):
    """Identifiers for supported covert SSH techniques."""

    DIRECT_SSH = "direct_ssh"
    STUNNEL_SSLH = "stunnel_sslh"
    WEBSOCKET_TLS = "websocket_tls"
    OBFS4 = "obfs4proxy"
    DNS_TUNNEL = "dns_tunnel"
    ICMP_TUNNEL = "icmp_tunnel"
    TOR = "tor_hidden_svc"
    SHADOWSOCKS = "shadowsocks"


@dataclass
class TechniqueScore:
    """Score and metadata for a single technique."""

    technique: TechniqueID
    name: str
    score: float = 0.0
    max_score: float = 10.0
    available: bool = True
    blocked: bool = False
    not_tested: bool = False
    justification: str = ""
    breakdown: dict[str, float] = field(default_factory=dict)

    @property
    def display_score(self) -> str:
        if self.blocked:
            return "Blocked"
        if self.not_tested:
            return "N/A"
        return f"{self.score:.1f}/10"


# Default weight configuration for scoring criteria
DEFAULT_WEIGHTS = {
    "channel_available": 3.0,   # Is the transport channel open?
    "dpi_resistance": 2.5,      # Resistance to Deep Packet Inspection
    "bandwidth": 1.5,           # Estimated bandwidth capacity
    "latency": 1.0,             # Connection latency
    "setup_complexity": 1.0,    # Ease of deployment (inverted: simpler = higher)
    "stealth": 1.0,             # How normal the traffic looks
}


class TechniqueScorer:
    """Scores covert SSH techniques based on network assessment results.

    The scorer takes probe results and produces a ranked list of viable
    techniques with scores and justifications.
    """

    def __init__(self, weights: dict[str, float] | None = None):
        self.weights = weights or DEFAULT_WEIGHTS.copy()

    def score_all(self, probes: dict) -> list[TechniqueScore]:
        """Score all techniques based on probe results.

        Args:
            probes: Dictionary with keys 'tcp', 'http', 'dns', 'icmp', 'dpi'
                   containing the respective probe result objects.

        Returns:
            List of TechniqueScore sorted by score descending.
        """
        tcp = probes.get("tcp")
        http = probes.get("http")
        dns = probes.get("dns")
        icmp = probes.get("icmp")
        dpi = probes.get("dpi")

        scores = [
            self._score_direct_ssh(tcp, dpi),
            self._score_stunnel_sslh(tcp, http, dpi),
            self._score_websocket_tls(tcp, http, dpi),
            self._score_obfs4(tcp, http, dpi),
            self._score_dns_tunnel(dns),
            self._score_icmp_tunnel(icmp),
            self._score_tor(tcp, dpi),
            self._score_shadowsocks(tcp, http, dpi),
        ]

        # Sort by score descending, blocked/not_tested last
        scores.sort(key=lambda s: (
            not s.blocked and not s.not_tested,
            s.score
        ), reverse=True)

        return scores

    def _normalize(self, value: float, max_val: float) -> float:
        """Normalize a value to 0-1 range."""
        if max_val <= 0:
            return 0.0
        return min(max(value / max_val, 0.0), 1.0)

    def _weighted_score(self, breakdown: dict[str, float]) -> float:
        """Calculate weighted score from breakdown components."""
        total = 0.0
        weight_sum = 0.0
        for key, raw_value in breakdown.items():
            w = self.weights.get(key, 1.0)
            total += raw_value * w
            weight_sum += w
        if weight_sum == 0:
            return 0.0
        return round((total / weight_sum) * 10, 1)

    def _score_direct_ssh(self, tcp, dpi) -> TechniqueScore:
        """Score direct SSH connection (port 22)."""
        ts = TechniqueScore(
            technique=TechniqueID.DIRECT_SSH,
            name="Direct SSH",
        )

        if tcp is None:
            ts.not_tested = True
            ts.justification = "TCP probe not performed"
            return ts

        port22 = tcp.ports.get(22)
        if port22 is None or port22.state != "open":
            ts.blocked = True
            ts.justification = "Port 22 filtered/closed"
            return ts

        breakdown = {
            "channel_available": 1.0,
            "dpi_resistance": 0.1,  # SSH is trivially detectable
            "bandwidth": 1.0,
            "latency": 1.0,
            "setup_complexity": 1.0,  # Simplest possible setup
            "stealth": 0.1,  # Very obvious
        }

        if dpi and dpi.dpi_detected:
            breakdown["dpi_resistance"] = 0.0
            ts.justification = "Port 22 open but DPI may inspect/block SSH"
        else:
            ts.justification = "Port 22 open, direct connection possible"

        ts.breakdown = breakdown
        ts.score = self._weighted_score(breakdown)
        return ts

    def _score_stunnel_sslh(self, tcp, http, dpi) -> TechniqueScore:
        """Score Stunnel + SSLH technique (SSH wrapped in TLS on port 443)."""
        ts = TechniqueScore(
            technique=TechniqueID.STUNNEL_SSLH,
            name="Stunnel+SSLH",
        )

        if tcp is None:
            ts.not_tested = True
            ts.justification = "TCP probe not performed"
            return ts

        port443 = tcp.ports.get(443)
        if port443 is None or port443.state != "open":
            ts.blocked = True
            ts.justification = "Port 443 not available"
            return ts

        tls_intercepted = http.tls_intercept if http else False
        dpi_active = dpi.dpi_detected if dpi else False
        ssh_in_tls_blocked = dpi.ssh_in_tls_blocked if dpi else False

        breakdown = {
            "channel_available": 1.0,
            "dpi_resistance": 0.7,
            "bandwidth": 0.95,
            "latency": 0.9,
            "setup_complexity": 0.7,
            "stealth": 0.7,
        }

        justifications = ["Port 443 open, TLS wrapping viable"]

        if tls_intercepted:
            breakdown["dpi_resistance"] -= 0.3
            breakdown["stealth"] -= 0.3
            justifications.append("TLS interception detected - may expose inner traffic")

        if dpi_active and ssh_in_tls_blocked:
            breakdown["dpi_resistance"] = 0.1
            justifications.append("DPI detects SSH inside TLS")
        elif dpi_active:
            breakdown["dpi_resistance"] -= 0.1
            justifications.append("DPI active but SSH-in-TLS not blocked")

        ts.breakdown = breakdown
        ts.score = self._weighted_score(breakdown)
        ts.justification = "; ".join(justifications)
        return ts

    def _score_websocket_tls(self, tcp, http, dpi) -> TechniqueScore:
        """Score WebSocket over TLS technique."""
        ts = TechniqueScore(
            technique=TechniqueID.WEBSOCKET_TLS,
            name="WebSocket/TLS",
        )

        if tcp is None:
            ts.not_tested = True
            ts.justification = "TCP probe not performed"
            return ts

        port443 = tcp.ports.get(443)
        if port443 is None or port443.state != "open":
            ts.blocked = True
            ts.justification = "Port 443 not available"
            return ts

        tls_intercepted = http.tls_intercept if http else False
        dpi_active = dpi.dpi_detected if dpi else False

        breakdown = {
            "channel_available": 1.0,
            "dpi_resistance": 0.8,
            "bandwidth": 0.9,
            "latency": 0.85,
            "setup_complexity": 0.65,
            "stealth": 0.85,
        }

        justifications = ["Port 443 open, WebSocket upgrade possible"]

        if tls_intercepted:
            breakdown["dpi_resistance"] -= 0.2
            breakdown["stealth"] -= 0.2
            justifications.append("TLS interception may inspect WebSocket frames")

        if dpi_active:
            breakdown["dpi_resistance"] -= 0.1
            justifications.append("DPI active but WebSocket is hard to fingerprint")

        # WebSocket is better than raw TLS for stealth because it looks like
        # legitimate web traffic
        if not dpi_active and not tls_intercepted:
            breakdown["stealth"] = 0.9
            justifications.append("No TLS intercept - traffic appears as normal HTTPS")

        ts.breakdown = breakdown
        ts.score = self._weighted_score(breakdown)
        ts.justification = "; ".join(justifications)
        return ts

    def _score_obfs4(self, tcp, http, dpi) -> TechniqueScore:
        """Score obfs4proxy technique (protocol obfuscation)."""
        ts = TechniqueScore(
            technique=TechniqueID.OBFS4,
            name="obfs4proxy",
        )

        if tcp is None:
            ts.not_tested = True
            ts.justification = "TCP probe not performed"
            return ts

        # obfs4 can work on any open port
        has_open_port = False
        for port_result in tcp.ports.values():
            if port_result.state == "open":
                has_open_port = True
                break

        if not has_open_port:
            ts.blocked = True
            ts.justification = "No open TCP ports found"
            return ts

        dpi_active = dpi.dpi_detected if dpi else False

        breakdown = {
            "channel_available": 1.0,
            "dpi_resistance": 0.95,
            "bandwidth": 0.85,
            "latency": 0.8,
            "setup_complexity": 0.5,
            "stealth": 0.95,
        }

        justifications = []

        if dpi_active:
            # obfs4 is specifically designed for DPI resistance
            justifications.append("DPI detected - obfs4 provides strong obfuscation")
            breakdown["dpi_resistance"] = 0.95
        else:
            justifications.append("No DPI detected, obfs4 still provides good stealth")

        ts.breakdown = breakdown
        ts.score = self._weighted_score(breakdown)
        ts.justification = "; ".join(justifications)
        return ts

    def _score_dns_tunnel(self, dns) -> TechniqueScore:
        """Score DNS tunneling technique."""
        ts = TechniqueScore(
            technique=TechniqueID.DNS_TUNNEL,
            name="DNS Tunnel",
        )

        if dns is None:
            ts.not_tested = True
            ts.justification = "DNS probe not performed"
            return ts

        if not dns.dns_open:
            ts.blocked = True
            ts.justification = "DNS resolution not working"
            return ts

        breakdown = {
            "channel_available": 1.0 if dns.tunnel_viable else 0.3,
            "dpi_resistance": 0.7,
            "bandwidth": 0.15,  # DNS tunnels are very slow
            "latency": 0.3,
            "setup_complexity": 0.4,
            "stealth": 0.6,
        }

        justifications = ["DNS resolution working"]

        if dns.dns_manipulated:
            breakdown["channel_available"] -= 0.3
            breakdown["stealth"] -= 0.2
            justifications.append("DNS manipulation detected - tunnel may be unreliable")

        if dns.nxdomain_hijack:
            breakdown["stealth"] -= 0.1
            justifications.append("NXDOMAIN hijacking - queries are monitored")

        bw = dns.estimated_bandwidth_kbps
        if bw > 0:
            justifications.append(f"Estimated bandwidth: ~{bw:.0f} Kbps")
            breakdown["bandwidth"] = min(bw / 500, 0.3)

        ts.breakdown = breakdown
        ts.score = self._weighted_score(breakdown)
        ts.justification = "; ".join(justifications)
        return ts

    def _score_icmp_tunnel(self, icmp) -> TechniqueScore:
        """Score ICMP tunneling technique."""
        ts = TechniqueScore(
            technique=TechniqueID.ICMP_TUNNEL,
            name="ICMP Tunnel",
        )

        if icmp is None or icmp.requires_root:
            ts.not_tested = True
            ts.justification = "ICMP probe not performed (requires root)"
            return ts

        if not icmp.icmp_allowed:
            ts.blocked = True
            ts.justification = "ICMP echo blocked"
            return ts

        breakdown = {
            "channel_available": 1.0,
            "dpi_resistance": 0.5,
            "bandwidth": 0.1,
            "latency": 0.4,
            "setup_complexity": 0.3,
            "stealth": 0.5,
        }

        justifications = [f"ICMP allowed (avg {icmp.avg_latency_ms:.0f}ms)"]

        if icmp.size_restricted:
            breakdown["bandwidth"] -= 0.05
            justifications.append("Payload size restricted")

        bw = icmp.estimated_bandwidth_kbps
        if bw > 0:
            justifications.append(f"Estimated bandwidth: ~{bw:.0f} Kbps")
            breakdown["bandwidth"] = min(bw / 200, 0.2)

        ts.breakdown = breakdown
        ts.score = self._weighted_score(breakdown)
        ts.justification = "; ".join(justifications)
        return ts

    def _score_tor(self, tcp, dpi) -> TechniqueScore:
        """Score Tor Hidden Service technique."""
        ts = TechniqueScore(
            technique=TechniqueID.TOR,
            name="Tor Hidden Svc",
        )

        # Tor requires outbound connectivity to the Tor network
        if tcp is None:
            ts.not_tested = True
            ts.justification = "TCP probe not performed"
            return ts

        # Tor needs at least one outbound port
        has_open = any(p.state == "open" for p in tcp.ports.values())
        if not has_open:
            ts.blocked = True
            ts.justification = "No outbound TCP connectivity"
            return ts

        dpi_active = dpi.dpi_detected if dpi else False

        breakdown = {
            "channel_available": 0.8,  # Tor availability not directly tested
            "dpi_resistance": 0.7,
            "bandwidth": 0.3,
            "latency": 0.2,
            "setup_complexity": 0.4,
            "stealth": 0.7,
        }

        justifications = ["Outbound connectivity available for Tor"]

        if dpi_active:
            breakdown["dpi_resistance"] = 0.5
            justifications.append("DPI may block Tor (use obfs4 bridge)")
        else:
            justifications.append("No DPI detected - Tor likely accessible")

        ts.breakdown = breakdown
        ts.score = self._weighted_score(breakdown)
        ts.justification = "; ".join(justifications)
        return ts

    def _score_shadowsocks(self, tcp, http, dpi) -> TechniqueScore:
        """Score Shadowsocks technique."""
        ts = TechniqueScore(
            technique=TechniqueID.SHADOWSOCKS,
            name="Shadowsocks",
        )

        if tcp is None:
            ts.not_tested = True
            ts.justification = "TCP probe not performed"
            return ts

        port443 = tcp.ports.get(443)
        has_open = any(p.state == "open" for p in tcp.ports.values())

        if not has_open:
            ts.blocked = True
            ts.justification = "No open TCP ports"
            return ts

        dpi_active = dpi.dpi_detected if dpi else False

        breakdown = {
            "channel_available": 1.0 if (port443 and port443.state == "open") else 0.7,
            "dpi_resistance": 0.85,
            "bandwidth": 0.9,
            "latency": 0.85,
            "setup_complexity": 0.55,
            "stealth": 0.8,
        }

        justifications = []

        if port443 and port443.state == "open":
            justifications.append("Port 443 available for Shadowsocks")
        else:
            justifications.append("Shadowsocks can use alternative port")

        if dpi_active:
            breakdown["dpi_resistance"] = 0.8
            justifications.append("DPI active - Shadowsocks AEAD provides good evasion")

        ts.breakdown = breakdown
        ts.score = self._weighted_score(breakdown)
        ts.justification = "; ".join(justifications)
        return ts
