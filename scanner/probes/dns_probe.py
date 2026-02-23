"""DNS probe for detecting DNS filtering and manipulation.

Compares DNS resolutions from the system resolver against well-known
public DNS servers to detect interception, redirection, or NXDOMAIN hijacking.
"""

import socket
import struct
import time
import random
from dataclasses import dataclass, field


@dataclass
class DNSProbeResult:
    """Results from DNS probe."""

    dns_open: bool = False
    dns_manipulated: bool = False
    system_resolver: str = ""
    system_answer: str = ""
    public_answer: str = ""
    nxdomain_hijack: bool = False
    nxdomain_details: str = ""
    latency_ms: float = 0.0
    udp53_open: bool = False
    tcp53_open: bool = False
    details: str = ""
    tunnel_viable: bool = False
    estimated_bandwidth_kbps: float = 0.0

    @property
    def summary(self) -> str:
        parts = []
        if self.dns_open:
            parts.append("DNS resolution working")
        else:
            parts.append("DNS resolution FAILED")
        if self.dns_manipulated:
            parts.append("DNS manipulation detected")
        if self.nxdomain_hijack:
            parts.append("NXDOMAIN hijacking detected")
        if self.tunnel_viable:
            parts.append(f"DNS tunnel viable (~{self.estimated_bandwidth_kbps:.0f} Kbps)")
        return "; ".join(parts)


# Public DNS servers for comparison
PUBLIC_DNS = [
    ("8.8.8.8", "Google"),
    ("1.1.1.1", "Cloudflare"),
    ("9.9.9.9", "Quad9"),
]

# Domain guaranteed to not exist, for NXDOMAIN hijack testing
NXDOMAIN_TEST = "thisdomainshouldneverexist12345.example.com"

# Well-known test domain for resolution comparison
TEST_DOMAIN = "dns.google"


class DNSProbe:
    """Detects DNS filtering, manipulation, and tunnel viability."""

    def __init__(self, target: str, domain: str | None = None,
                 timeout: float = 5.0):
        self.target = target
        self.domain = domain or TEST_DOMAIN
        self.timeout = timeout

    def _build_dns_query(self, domain: str, qtype: int = 1) -> bytes:
        """Build a raw DNS query packet.

        Args:
            domain: Domain name to query.
            qtype: Query type (1=A, 28=AAAA, 16=TXT).
        """
        txid = random.randint(0, 65535)
        flags = 0x0100  # Standard query, recursion desired
        header = struct.pack(">HHHHHH", txid, flags, 1, 0, 0, 0)

        qname = b""
        for label in domain.split("."):
            qname += struct.pack("B", len(label)) + label.encode()
        qname += b"\x00"

        question = qname + struct.pack(">HH", qtype, 1)  # IN class
        return header + question

    def _parse_dns_response(self, data: bytes) -> list[str]:
        """Extract A record IPs from a DNS response."""
        if len(data) < 12:
            return []

        ancount = struct.unpack(">H", data[6:8])[0]
        if ancount == 0:
            return []

        # Skip header and question section
        offset = 12
        # Skip QNAME
        while offset < len(data):
            length = data[offset]
            if length == 0:
                offset += 1
                break
            if length >= 192:  # Compression pointer
                offset += 2
                break
            offset += 1 + length
        offset += 4  # Skip QTYPE + QCLASS

        answers = []
        for _ in range(ancount):
            if offset >= len(data):
                break
            # Skip NAME (might be compressed)
            if data[offset] >= 192:
                offset += 2
            else:
                while offset < len(data) and data[offset] != 0:
                    offset += 1 + data[offset]
                offset += 1

            if offset + 10 > len(data):
                break

            rtype, rclass, ttl, rdlength = struct.unpack(
                ">HHIH", data[offset:offset + 10]
            )
            offset += 10

            if rtype == 1 and rdlength == 4:  # A record
                ip = ".".join(str(b) for b in data[offset:offset + 4])
                answers.append(ip)
            offset += rdlength

        return answers

    def _query_dns_server(self, server: str, domain: str) -> tuple[list[str], float]:
        """Send DNS query to a specific server and return answers + latency."""
        query = self._build_dns_query(domain)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)

        try:
            start = time.monotonic()
            sock.sendto(query, (server, 53))
            data, _ = sock.recvfrom(4096)
            latency = (time.monotonic() - start) * 1000
            answers = self._parse_dns_response(data)
            return answers, latency
        except (socket.timeout, OSError):
            return [], 0.0
        finally:
            sock.close()

    def _check_system_resolver(self, domain: str) -> tuple[str, float]:
        """Resolve domain using the system resolver."""
        try:
            start = time.monotonic()
            ip = socket.gethostbyname(domain)
            latency = (time.monotonic() - start) * 1000
            return ip, latency
        except socket.gaierror:
            return "", 0.0

    def _check_udp53_to_target(self) -> bool:
        """Check if UDP/53 is reachable to target (for DNS tunnel)."""
        query = self._build_dns_query("version.bind", qtype=16)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            sock.sendto(query, (self.target, 53))
            sock.recvfrom(4096)
            return True
        except (socket.timeout, OSError):
            return False
        finally:
            sock.close()

    def _check_tcp53_to_target(self) -> bool:
        """Check if TCP/53 is reachable to target."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect((self.target, 53))
            sock.close()
            return True
        except (socket.timeout, ConnectionError, OSError):
            return False

    def _check_nxdomain_hijack(self) -> tuple[bool, str]:
        """Check if NXDOMAIN responses are being hijacked."""
        sys_result, _ = self._check_system_resolver(NXDOMAIN_TEST)
        if sys_result:
            return True, f"NXDOMAIN hijacked to {sys_result}"
        return False, "NXDOMAIN responses are clean"

    def _estimate_tunnel_bandwidth(self) -> float:
        """Rough estimate of DNS tunnel bandwidth in Kbps.

        Sends multiple TXT queries and measures throughput.
        Typical DNS tunnel: 50-150 Kbps.
        """
        test_domains = [f"test{i}.{self.domain}" for i in range(5)]
        total_bytes = 0
        start = time.monotonic()

        for domain in test_domains:
            answers, _ = self._query_dns_server(PUBLIC_DNS[0][0], domain)
            if answers:
                total_bytes += 64  # Approximate useful bytes per response

        elapsed = time.monotonic() - start
        if elapsed > 0 and total_bytes > 0:
            return (total_bytes * 8) / elapsed / 1000
        return 0.0

    def run(self, simulate: bool = False) -> DNSProbeResult:
        """Execute DNS probe.

        Args:
            simulate: If True, return example data without making connections.
        """
        if simulate:
            return self._simulate()

        result = DNSProbeResult()

        # System resolver check
        sys_ip, sys_latency = self._check_system_resolver(self.domain)
        result.system_answer = sys_ip
        result.latency_ms = sys_latency
        result.dns_open = bool(sys_ip)

        # Compare with public DNS
        for server, name in PUBLIC_DNS:
            answers, _ = self._query_dns_server(server, self.domain)
            if answers:
                result.public_answer = answers[0]
                result.system_resolver = name
                break

        # Check for manipulation
        if result.system_answer and result.public_answer:
            if result.system_answer != result.public_answer:
                result.dns_manipulated = True
                result.details = (
                    f"System resolved to {result.system_answer}, "
                    f"public DNS to {result.public_answer}"
                )
            else:
                result.details = "DNS resolution consistent with public DNS"
        elif result.system_answer and not result.public_answer:
            result.details = "Could not reach public DNS for comparison"
        elif not result.system_answer:
            result.details = "System DNS resolution failed"

        # NXDOMAIN hijack check
        result.nxdomain_hijack, result.nxdomain_details = (
            self._check_nxdomain_hijack()
        )

        # Direct DNS to target
        result.udp53_open = self._check_udp53_to_target()
        result.tcp53_open = self._check_tcp53_to_target()

        # Tunnel viability
        result.tunnel_viable = result.dns_open and not result.dns_manipulated
        if result.tunnel_viable:
            result.estimated_bandwidth_kbps = self._estimate_tunnel_bandwidth()
            if result.estimated_bandwidth_kbps == 0:
                result.estimated_bandwidth_kbps = 80.0  # Conservative estimate

        return result

    def _simulate(self) -> DNSProbeResult:
        """Generate simulated results for demo/testing."""
        return DNSProbeResult(
            dns_open=True,
            dns_manipulated=False,
            system_resolver="Cloudflare",
            system_answer="203.0.113.50",
            public_answer="203.0.113.50",
            nxdomain_hijack=False,
            nxdomain_details="NXDOMAIN responses are clean",
            latency_ms=23.4,
            udp53_open=True,
            tcp53_open=True,
            details="DNS resolution consistent with public DNS",
            tunnel_viable=True,
            estimated_bandwidth_kbps=80.0,
        )
