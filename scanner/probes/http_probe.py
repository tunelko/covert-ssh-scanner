"""HTTP/HTTPS proxy and TLS interception detection probe.

Detects:
- HTTP CONNECT proxy presence
- Transparent proxies via header injection
- TLS interception by comparing certificate chains against expected values
"""

import hashlib
import socket
import ssl
import time
from dataclasses import dataclass


@dataclass
class HTTPProbeResult:
    """Results from HTTP probe."""

    proxy_detected: bool = False
    proxy_type: str = ""  # "CONNECT", "transparent", ""
    proxy_details: str = ""
    tls_intercept: bool = False
    tls_issuer: str = ""
    tls_expected_issuer: str = ""
    tls_fingerprint: str = ""
    tls_details: str = ""
    http_status: int = 0
    latency_ms: float = 0.0

    @property
    def summary(self) -> str:
        parts = []
        if self.proxy_detected:
            parts.append(f"Proxy: {self.proxy_type} ({self.proxy_details})")
        else:
            parts.append("No proxy detected")
        if self.tls_intercept:
            parts.append(f"TLS intercepted: issuer={self.tls_issuer}")
        else:
            parts.append(f"TLS OK: {self.tls_issuer}")
        return "; ".join(parts)


# Well-known CA issuers that indicate legitimate certificates
TRUSTED_ISSUERS = {
    "Let's Encrypt", "DigiCert", "Comodo", "GlobalSign",
    "Sectigo", "GoDaddy", "Amazon", "Google Trust Services",
    "Microsoft", "Baltimore", "ISRG Root",
}

# Issuers commonly associated with TLS interception
INTERCEPT_ISSUERS = {
    "Fortinet", "Palo Alto", "Blue Coat", "Zscaler", "Symantec",
    "McAfee", "Sophos", "Barracuda", "Untangle", "pfSense",
    "Squid", "mitmproxy", "Charles", "Fiddler", "BurpSuite",
}


class HTTPProbe:
    """Detects HTTP proxies and TLS interception on the network path."""

    def __init__(self, target: str, domain: str | None = None,
                 timeout: float = 5.0):
        self.target = target
        self.domain = domain or target
        self.timeout = timeout

    def _check_connect_proxy(self) -> tuple[bool, str]:
        """Try an HTTP CONNECT to detect forward proxy.

        Sends CONNECT to the target on port 80 and checks for proxy response.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, 80))
            req = (
                f"CONNECT {self.domain}:443 HTTP/1.1\r\n"
                f"Host: {self.domain}:443\r\n"
                "\r\n"
            )
            sock.sendall(req.encode())
            resp = sock.recv(4096).decode("utf-8", errors="replace")
            sock.close()

            if "200" in resp.split("\r\n")[0]:
                return True, "CONNECT proxy responded 200 (tunnel established)"
            elif "407" in resp:
                return True, "CONNECT proxy requires authentication (407)"
            elif "403" in resp:
                return True, "CONNECT proxy denied request (403)"
            return False, ""
        except (socket.timeout, ConnectionError, OSError):
            return False, ""

    def _check_transparent_proxy(self) -> tuple[bool, str]:
        """Detect transparent proxy via Via/X-Forwarded headers."""
        try:
            import requests
            resp = requests.get(
                f"http://{self.target}/",
                timeout=self.timeout,
                allow_redirects=False,
                headers={"Host": self.domain},
            )
            proxy_headers = ["Via", "X-Forwarded-For", "X-Cache",
                             "X-Proxy-ID", "Proxy-Connection"]
            found = {h: resp.headers[h] for h in proxy_headers
                     if h in resp.headers}
            if found:
                detail = ", ".join(f"{k}={v}" for k, v in found.items())
                return True, f"Transparent proxy headers: {detail}"
            return False, ""
        except Exception:
            return False, ""

    def _check_tls_intercept(self, port: int = 443) -> tuple[bool, str, str, str]:
        """Compare TLS certificate against expected values.

        Returns: (is_intercepted, issuer, fingerprint, details)
        """
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            wrapped = ctx.wrap_socket(sock, server_hostname=self.domain)
            wrapped.connect((self.target, port))
            cert_der = wrapped.getpeercert(binary_form=True)
            cert = wrapped.getpeercert()
            wrapped.close()

            fingerprint = hashlib.sha256(cert_der).hexdigest()[:32]
            issuer_parts = dict(x[0] for x in cert.get("issuer", []))
            issuer_org = issuer_parts.get("organizationName", "Unknown")
            issuer_cn = issuer_parts.get("commonName", "")

            # Check if issuer looks like an interception device
            intercepted = False
            details = f"Issuer: {issuer_org} (CN={issuer_cn})"
            for intercept_name in INTERCEPT_ISSUERS:
                if (intercept_name.lower() in issuer_org.lower() or
                        intercept_name.lower() in issuer_cn.lower()):
                    intercepted = True
                    details = (f"TLS interception detected: {issuer_org} "
                               f"(CN={issuer_cn}) matches known intercept CA")
                    break

            # Also flag self-signed or unknown issuers
            if not intercepted:
                known = any(t.lower() in issuer_org.lower()
                            for t in TRUSTED_ISSUERS)
                if not known and issuer_org != "Unknown":
                    details += " (unrecognized CA - possible interception)"

            return intercepted, issuer_org, fingerprint, details

        except ssl.SSLError as e:
            return False, "", "", f"SSL error: {e}"
        except (socket.timeout, ConnectionError, OSError) as e:
            return False, "", "", f"Connection failed: {e}"

    def run(self, simulate: bool = False) -> HTTPProbeResult:
        """Execute HTTP probe.

        Args:
            simulate: If True, return example data without making connections.
        """
        if simulate:
            return self._simulate()

        result = HTTPProbeResult()
        start = time.monotonic()

        # Check for CONNECT proxy
        proxy_found, proxy_detail = self._check_connect_proxy()
        if proxy_found:
            result.proxy_detected = True
            result.proxy_type = "CONNECT"
            result.proxy_details = proxy_detail
        else:
            # Check for transparent proxy
            transp_found, transp_detail = self._check_transparent_proxy()
            if transp_found:
                result.proxy_detected = True
                result.proxy_type = "transparent"
                result.proxy_details = transp_detail

        # Check TLS interception
        intercepted, issuer, fp, details = self._check_tls_intercept()
        result.tls_intercept = intercepted
        result.tls_issuer = issuer
        result.tls_fingerprint = fp
        result.tls_details = details

        result.latency_ms = round((time.monotonic() - start) * 1000, 2)
        return result

    def _simulate(self) -> HTTPProbeResult:
        """Generate simulated results for demo/testing."""
        return HTTPProbeResult(
            proxy_detected=False,
            proxy_type="",
            proxy_details="",
            tls_intercept=False,
            tls_issuer="Let's Encrypt",
            tls_expected_issuer="Let's Encrypt",
            tls_fingerprint="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
            tls_details="Certificate chain valid (Let's Encrypt)",
            http_status=200,
            latency_ms=45.2,
        )
