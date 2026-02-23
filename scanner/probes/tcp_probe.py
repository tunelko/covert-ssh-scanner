"""TCP port scanning and service detection probe.

Detects open/filtered/closed ports and identifies running services
by analyzing banners and handshake behavior.
"""

import socket
import time
from dataclasses import dataclass, field


@dataclass
class PortResult:
    """Result of probing a single TCP port."""

    port: int
    state: str  # "open", "filtered", "closed"
    banner: str = ""
    latency_ms: float = 0.0
    service: str = ""


@dataclass
class TCPProbeResult:
    """Aggregated results from TCP probe."""

    ports: dict[int, PortResult] = field(default_factory=dict)
    source_ip: str = ""
    target_ip: str = ""

    @property
    def open_ports(self) -> list[int]:
        return [p for p, r in self.ports.items() if r.state == "open"]

    @property
    def filtered_ports(self) -> list[int]:
        return [p for p, r in self.ports.items() if r.state == "filtered"]


# Standard ports to probe for covert channel viability
DEFAULT_PORTS = [22, 80, 443, 53, 8443, 8080, 993, 995, 587]

# Known service banners
SERVICE_SIGNATURES = {
    "SSH": "SSH-",
    "HTTP": "HTTP/",
    "SMTP": "220 ",
    "FTP": "220 ",
    "IMAP": "* OK",
}


class TCPProbe:
    """Probes TCP ports to determine open/filtered/closed state and service banners."""

    def __init__(self, target: str, ports: list[int] | None = None,
                 timeout: float = 3.0):
        self.target = target
        self.ports = ports or DEFAULT_PORTS
        self.timeout = timeout

    def _resolve_target(self) -> str:
        """Resolve hostname to IP address."""
        try:
            return socket.gethostbyname(self.target)
        except socket.gaierror:
            return self.target

    def _probe_port(self, ip: str, port: int) -> PortResult:
        """Probe a single TCP port and grab banner if possible."""
        result = PortResult(port=port, state="filtered")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            start = time.monotonic()
            sock.connect((ip, port))
            elapsed = (time.monotonic() - start) * 1000
            result.state = "open"
            result.latency_ms = round(elapsed, 2)

            # Try to grab banner
            try:
                sock.settimeout(2.0)
                banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
                result.banner = banner[:256]

                for service, sig in SERVICE_SIGNATURES.items():
                    if banner.startswith(sig):
                        result.service = service
                        break
            except (socket.timeout, ConnectionError, OSError):
                pass

            # If no banner received, identify by port convention
            if not result.service:
                result.service = _port_service_hint(port)

        except socket.timeout:
            result.state = "filtered"
        except ConnectionRefusedError:
            result.state = "closed"
        except OSError:
            result.state = "filtered"
        finally:
            sock.close()

        return result

    def run(self, simulate: bool = False) -> TCPProbeResult:
        """Execute TCP probe against all configured ports.

        Args:
            simulate: If True, return example data without making connections.
        """
        if simulate:
            return self._simulate()

        ip = self._resolve_target()
        result = TCPProbeResult(target_ip=ip)

        # Detect our own source IP
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((ip, 80))
            result.source_ip = s.getsockname()[0]
            s.close()
        except OSError:
            result.source_ip = "unknown"

        for port in self.ports:
            port_result = self._probe_port(ip, port)
            result.ports[port] = port_result

        return result

    def _simulate(self) -> TCPProbeResult:
        """Generate simulated results for demo/testing."""
        result = TCPProbeResult(
            target_ip="203.0.113.50",
            source_ip="192.168.1.100",
        )
        simulated = {
            22: PortResult(22, "filtered", latency_ms=0, service="SSH"),
            80: PortResult(80, "open", "HTTP/1.1 200 OK", 15.3, "HTTP"),
            443: PortResult(443, "open", "", 18.7, "HTTPS"),
            53: PortResult(53, "open", "", 12.1, "DNS"),
            8443: PortResult(8443, "filtered", latency_ms=0),
            8080: PortResult(8080, "closed", latency_ms=0),
            993: PortResult(993, "filtered", latency_ms=0),
            995: PortResult(995, "filtered", latency_ms=0),
            587: PortResult(587, "filtered", latency_ms=0),
        }
        for port in self.ports:
            if port in simulated:
                result.ports[port] = simulated[port]
            else:
                result.ports[port] = PortResult(port, "filtered")
        return result


def _port_service_hint(port: int) -> str:
    """Return likely service name based on well-known port numbers."""
    hints = {
        22: "SSH", 80: "HTTP", 443: "HTTPS", 53: "DNS",
        8443: "HTTPS-ALT", 8080: "HTTP-ALT", 993: "IMAPS",
        995: "POP3S", 587: "SUBMISSION",
    }
    return hints.get(port, "")
