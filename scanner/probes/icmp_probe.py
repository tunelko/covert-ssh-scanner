"""ICMP probe for detecting ping availability and tunnel viability.

Requires root privileges for raw socket operations.
Tests ICMP echo with variable payload sizes to detect filtering.
"""

import os
import struct
import socket
import time
from dataclasses import dataclass


@dataclass
class ICMPProbeResult:
    """Results from ICMP probe."""

    icmp_allowed: bool = False
    requires_root: bool = False
    avg_latency_ms: float = 0.0
    min_latency_ms: float = 0.0
    max_latency_ms: float = 0.0
    packet_loss_pct: float = 100.0
    max_payload_size: int = 0
    size_restricted: bool = False
    tunnel_viable: bool = False
    estimated_bandwidth_kbps: float = 0.0
    details: str = ""

    @property
    def summary(self) -> str:
        if not self.icmp_allowed:
            return "ICMP blocked or requires root"
        restriction = "size restricted" if self.size_restricted else "no size restriction"
        return (
            f"ICMP allowed (avg {self.avg_latency_ms:.0f}ms, "
            f"{restriction}, ~{self.estimated_bandwidth_kbps:.0f} Kbps)"
        )


class ICMPProbe:
    """Detects ICMP availability and characterizes the channel for tunneling."""

    def __init__(self, target: str, timeout: float = 3.0, count: int = 5):
        self.target = target
        self.timeout = timeout
        self.count = count

    @staticmethod
    def _checksum(data: bytes) -> int:
        """Calculate ICMP checksum."""
        if len(data) % 2:
            data += b"\x00"
        s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
        s = (s >> 16) + (s & 0xFFFF)
        s += s >> 16
        return ~s & 0xFFFF

    def _build_echo_request(self, identifier: int, seq: int,
                            payload_size: int = 56) -> bytes:
        """Build an ICMP echo request packet."""
        icmp_type = 8  # Echo request
        code = 0
        checksum = 0
        payload = bytes(range(payload_size % 256)) * (payload_size // 256 + 1)
        payload = payload[:payload_size]

        header = struct.pack("!BBHHH", icmp_type, code, checksum,
                             identifier, seq)
        checksum = self._checksum(header + payload)
        header = struct.pack("!BBHHH", icmp_type, code, checksum,
                             identifier, seq)
        return header + payload

    def _send_ping(self, payload_size: int = 56) -> tuple[bool, float]:
        """Send a single ICMP echo and wait for reply.

        Returns: (success, latency_ms)
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                 socket.IPPROTO_ICMP)
            sock.settimeout(self.timeout)
        except PermissionError:
            return False, 0.0

        identifier = os.getpid() & 0xFFFF
        packet = self._build_echo_request(identifier, 1, payload_size)

        try:
            target_ip = socket.gethostbyname(self.target)
            start = time.monotonic()
            sock.sendto(packet, (target_ip, 0))

            while True:
                data, addr = sock.recvfrom(65535)
                elapsed = (time.monotonic() - start) * 1000

                # Parse IP header (20 bytes min) + ICMP header
                if len(data) >= 28:
                    ip_header_len = (data[0] & 0x0F) * 4
                    icmp_data = data[ip_header_len:]
                    icmp_type = icmp_data[0]
                    recv_id = struct.unpack("!H", icmp_data[4:6])[0]

                    if icmp_type == 0 and recv_id == identifier:  # Echo reply
                        return True, elapsed

                if elapsed > self.timeout * 1000:
                    break

            return False, 0.0
        except (socket.timeout, OSError):
            return False, 0.0
        finally:
            sock.close()

    def _test_payload_sizes(self) -> tuple[int, bool]:
        """Test various payload sizes to detect size restrictions.

        Returns: (max_working_size, is_restricted)
        """
        sizes = [56, 128, 256, 512, 1024, 1400]
        max_working = 0

        for size in sizes:
            success, _ = self._send_ping(size)
            if success:
                max_working = size
            else:
                break

        restricted = max_working < 1400 and max_working > 0
        return max_working, restricted

    def run(self, simulate: bool = False) -> ICMPProbeResult:
        """Execute ICMP probe.

        Args:
            simulate: If True, return example data without making connections.
        """
        if simulate:
            return self._simulate()

        result = ICMPProbeResult()

        # Check if we have root
        if os.geteuid() != 0:
            result.requires_root = True
            result.details = "Root privileges required for ICMP probing"
            return result

        # Send pings and collect latencies
        latencies = []
        sent = 0
        received = 0

        for _ in range(self.count):
            sent += 1
            success, latency = self._send_ping()
            if success:
                received += 1
                latencies.append(latency)

        if latencies:
            result.icmp_allowed = True
            result.avg_latency_ms = round(sum(latencies) / len(latencies), 2)
            result.min_latency_ms = round(min(latencies), 2)
            result.max_latency_ms = round(max(latencies), 2)
            result.packet_loss_pct = round((1 - received / sent) * 100, 1)

            # Test payload sizes
            result.max_payload_size, result.size_restricted = (
                self._test_payload_sizes()
            )

            # Estimate tunnel bandwidth
            # ICMP tunnel: ~1-5 pps usable, max_payload useful bytes
            usable_bytes = min(result.max_payload_size, 512)
            pps = 5  # Conservative packets per second
            result.estimated_bandwidth_kbps = round(
                (usable_bytes * pps * 8) / 1000, 1
            )
            result.tunnel_viable = result.estimated_bandwidth_kbps > 5

            result.details = (
                f"ICMP echo working: {received}/{sent} replies, "
                f"max payload {result.max_payload_size}B"
            )
        else:
            result.details = "No ICMP echo replies received"

        return result

    def _simulate(self) -> ICMPProbeResult:
        """Generate simulated results for demo/testing."""
        return ICMPProbeResult(
            icmp_allowed=True,
            requires_root=False,
            avg_latency_ms=23.0,
            min_latency_ms=18.5,
            max_latency_ms=31.2,
            packet_loss_pct=0.0,
            max_payload_size=1400,
            size_restricted=False,
            tunnel_viable=True,
            estimated_bandwidth_kbps=20.0,
            details="ICMP echo working: 5/5 replies, max payload 1400B",
        )
