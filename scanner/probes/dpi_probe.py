"""Deep Packet Inspection (DPI) detection probe.

Detects active DPI by sending protocol-specific banners on unexpected
ports and observing if connections are terminated.
"""

import socket
import ssl
import time
from dataclasses import dataclass


@dataclass
class DPIProbeResult:
    """Results from DPI detection probe."""

    dpi_detected: bool = False
    ssh_banner_blocked: bool = False
    ssh_banner_port: int = 0
    ssh_in_tls_blocked: bool = False
    protocol_enforcement: bool = False
    details: str = ""
    latency_ms: float = 0.0
    tests_performed: list[str] | None = None
    test_results: dict[str, str] | None = None

    def __post_init__(self):
        if self.tests_performed is None:
            self.tests_performed = []
        if self.test_results is None:
            self.test_results = {}

    @property
    def summary(self) -> str:
        if self.dpi_detected:
            issues = []
            if self.ssh_banner_blocked:
                issues.append(f"SSH banner RST on :{self.ssh_banner_port}")
            if self.ssh_in_tls_blocked:
                issues.append("SSH-in-TLS detected")
            if self.protocol_enforcement:
                issues.append("Protocol enforcement active")
            return f"DPI detected: {', '.join(issues)}"
        return "No DPI detected"


class DPIProbe:
    """Detects Deep Packet Inspection by testing protocol behavior on various ports.

    Requires root privileges for some tests (raw socket banner injection).
    """

    def __init__(self, target: str, timeout: float = 5.0):
        self.target = target
        self.timeout = timeout

    def _test_ssh_banner_on_port(self, port: int) -> tuple[bool, str]:
        """Send SSH banner on a non-SSH port to detect protocol-aware DPI.

        If DPI is active, the connection will be RST or dropped after
        sending an SSH-2.0 banner on a port like 443 or 80.

        Returns: (blocked, detail_string)
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, port))

            # Send SSH banner
            ssh_banner = b"SSH-2.0-OpenSSH_8.9 test\r\n"
            sock.sendall(ssh_banner)

            # Try to receive response
            try:
                response = sock.recv(1024)
                if response:
                    resp_str = response.decode("utf-8", errors="replace")
                    if resp_str.startswith("SSH-"):
                        return False, f"Port {port}: SSH server responded (legitimate SSH)"
                    return False, f"Port {port}: Got response (no DPI block)"
                else:
                    return True, f"Port {port}: Empty response after SSH banner (possible DPI)"
            except (ConnectionResetError, BrokenPipeError):
                return True, f"Port {port}: Connection RST after SSH banner (DPI detected)"
            except socket.timeout:
                return False, f"Port {port}: Timeout (inconclusive)"

        except (socket.timeout, ConnectionError, OSError) as e:
            return False, f"Port {port}: Could not connect ({e})"
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def _test_ssh_in_tls(self, port: int = 443) -> tuple[bool, str]:
        """Test if SSH traffic inside TLS is detected.

        Establishes a TLS connection and then sends an SSH banner inside it.
        Sophisticated DPI can detect this via traffic analysis (packet sizes/timing).
        """
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            wrapped = ctx.wrap_socket(sock, server_hostname=self.target)
            wrapped.connect((self.target, port))

            # Send SSH banner inside TLS tunnel
            wrapped.sendall(b"SSH-2.0-OpenSSH_8.9 test\r\n")

            try:
                response = wrapped.recv(1024)
                if not response:
                    wrapped.close()
                    return True, "SSH-in-TLS: Empty response (possible DPI on TLS content)"
                wrapped.close()
                return False, "SSH-in-TLS: Got response (no content inspection)"
            except (ConnectionResetError, BrokenPipeError):
                return True, "SSH-in-TLS: Connection RST (TLS content inspection active)"
            except ssl.SSLError:
                return True, "SSH-in-TLS: SSL error after banner (possible DPI)"
            except socket.timeout:
                wrapped.close()
                return False, "SSH-in-TLS: Timeout (inconclusive)"

        except (ssl.SSLError, socket.timeout, ConnectionError, OSError) as e:
            return False, f"SSH-in-TLS: Could not establish TLS ({e})"

    def _test_protocol_enforcement(self, port: int = 80) -> tuple[bool, str]:
        """Test if the network enforces specific protocols on standard ports.

        Sends garbage data on port 80 to see if non-HTTP traffic is blocked.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, port))

            # Send non-HTTP garbage
            garbage = b"\x00\x01\x02NOTHTTP\xff\xfe\xfd\r\n"
            sock.sendall(garbage)

            try:
                response = sock.recv(1024)
                sock.close()
                if not response:
                    return True, "Port 80: Non-HTTP data got empty response (enforcement)"
                return False, "Port 80: Non-HTTP data accepted"
            except (ConnectionResetError, BrokenPipeError):
                return True, "Port 80: Non-HTTP data caused RST (protocol enforcement)"
            except socket.timeout:
                sock.close()
                return False, "Port 80: Timeout on non-HTTP data (inconclusive)"

        except (socket.timeout, ConnectionError, OSError) as e:
            return False, f"Port 80: Could not connect ({e})"

    def run(self, simulate: bool = False) -> DPIProbeResult:
        """Execute DPI detection probe.

        Args:
            simulate: If True, return example data without making connections.
        """
        if simulate:
            return self._simulate()

        result = DPIProbeResult()
        start = time.monotonic()

        # Test SSH banner on port 443
        result.tests_performed.append("ssh_banner_443")
        blocked_443, detail_443 = self._test_ssh_banner_on_port(443)
        result.test_results["ssh_banner_443"] = detail_443

        # Test SSH banner on port 80
        result.tests_performed.append("ssh_banner_80")
        blocked_80, detail_80 = self._test_ssh_banner_on_port(80)
        result.test_results["ssh_banner_80"] = detail_80

        if blocked_443 or blocked_80:
            result.ssh_banner_blocked = True
            result.ssh_banner_port = 443 if blocked_443 else 80
            result.dpi_detected = True

        # Test SSH inside TLS
        result.tests_performed.append("ssh_in_tls")
        tls_blocked, tls_detail = self._test_ssh_in_tls()
        result.test_results["ssh_in_tls"] = tls_detail
        if tls_blocked:
            result.ssh_in_tls_blocked = True
            result.dpi_detected = True

        # Test protocol enforcement
        result.tests_performed.append("protocol_enforcement")
        proto_blocked, proto_detail = self._test_protocol_enforcement()
        result.test_results["protocol_enforcement"] = proto_detail
        if proto_blocked:
            result.protocol_enforcement = True

        result.latency_ms = round((time.monotonic() - start) * 1000, 2)

        # Build summary details
        findings = []
        if result.ssh_banner_blocked:
            findings.append(f"SSH banner blocked on port {result.ssh_banner_port}")
        if result.ssh_in_tls_blocked:
            findings.append("SSH traffic detected inside TLS")
        if result.protocol_enforcement:
            findings.append("Protocol enforcement on port 80")
        if not findings:
            findings.append("No DPI indicators found")
        result.details = "; ".join(findings)

        return result

    def _simulate(self) -> DPIProbeResult:
        """Generate simulated results for demo/testing."""
        return DPIProbeResult(
            dpi_detected=True,
            ssh_banner_blocked=True,
            ssh_banner_port=443,
            ssh_in_tls_blocked=False,
            protocol_enforcement=False,
            details="SSH banner on :443 was RST (probable DPI)",
            latency_ms=120.5,
            tests_performed=[
                "ssh_banner_443", "ssh_banner_80",
                "ssh_in_tls", "protocol_enforcement",
            ],
            test_results={
                "ssh_banner_443": "Port 443: Connection RST after SSH banner (DPI detected)",
                "ssh_banner_80": "Port 80: Got response (no DPI block)",
                "ssh_in_tls": "SSH-in-TLS: Got response (no content inspection)",
                "protocol_enforcement": "Port 80: Non-HTTP data accepted",
            },
        )
