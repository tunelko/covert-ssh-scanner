"""Experimental HTTP steganography module.

Hides arbitrary data (SSH traffic) inside HTTP requests/responses that
mimic legitimate web browsing. This is a proof-of-concept demonstrating
the concept of protocol-level steganography.

Encoding channels:
- Cookie headers with base64 data resembling session tokens
- Query parameters resembling analytics/tracking data
- POST bodies formatted as JSON API responses
- User-Agent rotation to mimic real browser diversity
- Timing jitter to avoid traffic analysis

This module implements both a client encoder (data -> HTTP requests)
and a server decoder (HTTP requests -> data), as well as a simple
proxy that bridges SSH through HTTP steganography.
"""

import base64
import hashlib
import json
import os
import random
import socket
import struct
import threading
import time
from dataclasses import dataclass
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlencode, parse_qs, urlparse


# User-Agent strings for rotation (mimics diverse browsers)
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
]

# Fake URL paths that look like real web traffic
COVER_PATHS = [
    "/api/v2/analytics/collect",
    "/api/v1/events/track",
    "/cdn/assets/config.json",
    "/api/v2/user/preferences",
    "/static/js/bundle.min.js",
    "/api/v1/health",
    "/pixel.gif",
    "/api/v2/telemetry",
]

# Cookie name patterns that look legitimate
COOKIE_NAMES = [
    "_ga", "_gid", "_fbp", "session_id", "csrf_token",
    "prefs", "lang", "theme", "__cfduid",
]

# Magic byte to identify stego packets
STEGO_MAGIC = b"\xDE\xAD"

# Max data per HTTP request (to look realistic)
MAX_CHUNK_SIZE = 1024


@dataclass
class StegoStats:
    """Statistics for steganographic channel."""

    bytes_sent: int = 0
    bytes_received: int = 0
    requests_sent: int = 0
    requests_received: int = 0
    start_time: float = 0.0

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.start_time if self.start_time else 0

    @property
    def bandwidth_bps(self) -> float:
        if self.elapsed == 0:
            return 0
        return (self.bytes_sent + self.bytes_received) * 8 / self.elapsed


class StegoEncoder:
    """Encodes binary data into innocuous-looking HTTP components."""

    def __init__(self, key: str = "default"):
        self.key = key.encode()
        self._seq = 0

    def _xor_mask(self, data: bytes) -> bytes:
        """Simple XOR masking with key-derived stream."""
        key_hash = hashlib.sha256(self.key).digest()
        masked = bytearray(len(data))
        for i, b in enumerate(data):
            masked[i] = b ^ key_hash[i % len(key_hash)]
        return bytes(masked)

    def encode_to_cookie(self, data: bytes) -> dict[str, str]:
        """Encode data into cookie-like headers.

        Data is split across multiple cookie values that look like
        tracking/session tokens.
        """
        masked = self._xor_mask(data)
        encoded = base64.urlsafe_b64encode(
            STEGO_MAGIC + struct.pack(">H", self._seq) + masked
        ).decode().rstrip("=")
        self._seq = (self._seq + 1) % 65536

        # Split across cookie names
        cookies = {}
        chunk_size = max(20, len(encoded) // 3)
        parts = [encoded[i:i + chunk_size]
                 for i in range(0, len(encoded), chunk_size)]

        for i, part in enumerate(parts):
            name = COOKIE_NAMES[i % len(COOKIE_NAMES)]
            cookies[name] = part

        return cookies

    def encode_to_query(self, data: bytes) -> str:
        """Encode data into URL query parameters resembling analytics."""
        masked = self._xor_mask(data)
        encoded = base64.urlsafe_b64encode(
            STEGO_MAGIC + struct.pack(">H", self._seq) + masked
        ).decode().rstrip("=")
        self._seq = (self._seq + 1) % 65536

        params = {
            "utm_source": encoded[:32] if len(encoded) > 32 else encoded,
            "utm_medium": "organic",
            "utm_campaign": encoded[32:64] if len(encoded) > 32 else "default",
            "v": "2",
            "tid": f"UA-{random.randint(100000, 999999)}-1",
            "t": "pageview",
        }
        if len(encoded) > 64:
            params["cd1"] = encoded[64:]

        return urlencode(params)

    def encode_to_json_body(self, data: bytes) -> str:
        """Encode data into a JSON body that looks like an API payload."""
        masked = self._xor_mask(data)
        encoded = base64.b64encode(
            STEGO_MAGIC + struct.pack(">H", self._seq) + masked
        ).decode()
        self._seq = (self._seq + 1) % 65536

        payload = {
            "events": [
                {
                    "type": "interaction",
                    "timestamp": int(time.time() * 1000),
                    "session_id": hashlib.md5(
                        str(self._seq).encode()
                    ).hexdigest(),
                    "data": encoded,
                    "metadata": {
                        "page": random.choice(["/home", "/about", "/products"]),
                        "referrer": "https://www.google.com/",
                        "screen": "1920x1080",
                    },
                }
            ],
            "client_id": hashlib.sha256(self.key).hexdigest()[:16],
            "version": "2.1.0",
        }
        return json.dumps(payload)

    def build_request(self, data: bytes, method: str = "auto") -> dict:
        """Build a complete HTTP request carrying hidden data.

        Returns dict with: method, path, headers, body
        """
        if method == "auto":
            method = "POST" if len(data) > 128 else "GET"

        path = random.choice(COVER_PATHS)
        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "application/json, text/html, */*",
            "Accept-Language": "en-US,en;q=0.9,es;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
        }

        body = None

        if method == "GET":
            query = self.encode_to_query(data)
            path = f"{path}?{query}"
            cookies = self.encode_to_cookie(data)
            headers["Cookie"] = "; ".join(
                f"{k}={v}" for k, v in cookies.items()
            )
        else:
            body = self.encode_to_json_body(data)
            headers["Content-Type"] = "application/json"
            headers["Content-Length"] = str(len(body))
            # Also put some data in cookies for redundancy
            cookies = self.encode_to_cookie(data[:64] if len(data) > 64 else data)
            headers["Cookie"] = "; ".join(
                f"{k}={v}" for k, v in cookies.items()
            )

        return {
            "method": method,
            "path": path,
            "headers": headers,
            "body": body,
        }


class StegoDecoder:
    """Decodes data hidden in HTTP requests by StegoEncoder."""

    def __init__(self, key: str = "default"):
        self.key = key.encode()

    def _xor_unmask(self, data: bytes) -> bytes:
        """Reverse XOR masking."""
        key_hash = hashlib.sha256(self.key).digest()
        unmasked = bytearray(len(data))
        for i, b in enumerate(data):
            unmasked[i] = b ^ key_hash[i % len(key_hash)]
        return bytes(unmasked)

    def _decode_base64(self, encoded: str) -> tuple[int, bytes] | None:
        """Decode base64 stego data, returning (seq, data) or None."""
        # Re-add padding
        padding = 4 - (len(encoded) % 4)
        if padding != 4:
            encoded += "=" * padding

        try:
            raw = base64.urlsafe_b64decode(encoded)
        except Exception:
            try:
                raw = base64.b64decode(encoded)
            except Exception:
                return None

        if len(raw) < 4:
            return None

        if raw[:2] != STEGO_MAGIC:
            return None

        seq = struct.unpack(">H", raw[2:4])[0]
        payload = self._xor_unmask(raw[4:])
        return seq, payload

    def decode_from_cookies(self, cookie_header: str) -> bytes | None:
        """Extract hidden data from Cookie header."""
        if not cookie_header:
            return None

        # Reconstruct the encoded string from cookie values
        cookies = {}
        for part in cookie_header.split(";"):
            part = part.strip()
            if "=" in part:
                name, value = part.split("=", 1)
                cookies[name.strip()] = value.strip()

        # Try concatenating known cookie names
        encoded_parts = []
        for name in COOKIE_NAMES:
            if name in cookies:
                encoded_parts.append(cookies[name])

        if not encoded_parts:
            return None

        encoded = "".join(encoded_parts)
        result = self._decode_base64(encoded)
        return result[1] if result else None

    def decode_from_query(self, query_string: str) -> bytes | None:
        """Extract hidden data from query parameters."""
        params = parse_qs(query_string)

        # Reconstruct encoded data from analytics-like params
        parts = []
        for key in ["utm_source", "utm_campaign", "cd1"]:
            if key in params:
                val = params[key][0]
                if val != "organic" and val != "default":
                    parts.append(val)

        if not parts:
            return None

        encoded = "".join(parts)
        result = self._decode_base64(encoded)
        return result[1] if result else None

    def decode_from_json_body(self, body: str) -> bytes | None:
        """Extract hidden data from JSON body."""
        try:
            payload = json.loads(body)
            events = payload.get("events", [])
            if events and "data" in events[0]:
                encoded = events[0]["data"]
                result = self._decode_base64(encoded)
                return result[1] if result else None
        except (json.JSONDecodeError, KeyError, IndexError):
            pass
        return None

    def decode_request(self, method: str, path: str,
                       headers: dict, body: str | None) -> bytes | None:
        """Attempt to decode hidden data from an HTTP request.

        Tries all encoding channels and returns the first successful decode.
        """
        # Try JSON body first (most data)
        if body and method == "POST":
            data = self.decode_from_json_body(body)
            if data:
                return data

        # Try query parameters
        if "?" in path:
            query = path.split("?", 1)[1]
            data = self.decode_from_query(query)
            if data:
                return data

        # Try cookies
        cookie = headers.get("Cookie", headers.get("cookie", ""))
        if cookie:
            data = self.decode_from_cookies(cookie)
            if data:
                return data

        return None


class HTTPStegoServer(BaseHTTPRequestHandler):
    """HTTP server that decodes steganographic data and proxies to SSH.

    This is a PoC server that receives HTTP requests with hidden data,
    decodes them, and forwards to a local SSH server.
    """

    decoder = StegoDecoder()
    encoder = StegoEncoder()
    ssh_host = "127.0.0.1"
    ssh_port = 22
    stats = StegoStats()
    _ssh_connections: dict[str, socket.socket] = {}

    def log_message(self, format, *args):
        """Suppress default HTTP logging."""
        pass

    def _get_session_id(self) -> str:
        """Extract session identifier from request."""
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            if "session_id=" in part:
                return part.split("=", 1)[1].strip()
        return self.client_address[0]

    def do_GET(self):
        """Handle GET requests with hidden data in query/cookies."""
        data = self.decoder.decode_request(
            "GET", self.path, dict(self.headers), None
        )

        if data:
            self.__class__.stats.bytes_received += len(data)
            self.__class__.stats.requests_received += 1

            # Forward to SSH and get response
            response_data = self._forward_to_ssh(data)
            self._send_stego_response(response_data)
        else:
            # Serve a decoy page
            self._send_decoy_response()

    def do_POST(self):
        """Handle POST requests with hidden data in body."""
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="replace")

        data = self.decoder.decode_request(
            "POST", self.path, dict(self.headers), body
        )

        if data:
            self.__class__.stats.bytes_received += len(data)
            self.__class__.stats.requests_received += 1

            response_data = self._forward_to_ssh(data)
            self._send_stego_response(response_data)
        else:
            self._send_decoy_response()

    def _forward_to_ssh(self, data: bytes) -> bytes:
        """Forward decoded data to local SSH server."""
        session_id = self._get_session_id()

        try:
            if session_id not in self.__class__._ssh_connections:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5.0)
                sock.connect((self.__class__.ssh_host, self.__class__.ssh_port))
                self.__class__._ssh_connections[session_id] = sock

            sock = self.__class__._ssh_connections[session_id]
            sock.sendall(data)
            sock.settimeout(1.0)

            try:
                response = sock.recv(4096)
                return response
            except socket.timeout:
                return b""

        except (ConnectionError, OSError):
            self.__class__._ssh_connections.pop(session_id, None)
            return b""

    def _send_stego_response(self, data: bytes):
        """Send HTTP response with hidden data."""
        if data:
            body = self.encoder.encode_to_json_body(data)
            self.__class__.stats.bytes_sent += len(data)
        else:
            body = json.dumps({
                "status": "ok",
                "timestamp": int(time.time() * 1000),
            })

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache, no-store")
        self.send_header("X-Request-Id", hashlib.md5(
            str(time.time()).encode()
        ).hexdigest()[:8])
        self.end_headers()
        self.wfile.write(body.encode())
        self.__class__.stats.requests_sent += 1

    def _send_decoy_response(self):
        """Send a realistic-looking decoy response."""
        decoy = {
            "status": "ok",
            "version": "2.1.0",
            "timestamp": int(time.time() * 1000),
            "server": "api-gateway",
        }
        body = json.dumps(decoy)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "nginx/1.24.0")
        self.end_headers()
        self.wfile.write(body.encode())


class HTTPStegoClient:
    """Client that encodes data into HTTP requests for steganographic transport.

    Provides a socket-like interface that sends/receives data through
    HTTP steganography to a remote HTTPStegoServer.
    """

    def __init__(self, server_url: str, key: str = "default"):
        self.server_url = server_url.rstrip("/")
        self.encoder = StegoEncoder(key)
        self.decoder = StegoDecoder(key)
        self.stats = StegoStats(start_time=time.monotonic())
        self._running = False

    def send(self, data: bytes) -> bytes:
        """Send data through HTTP steganography and return response data.

        Encodes data into an HTTP request, sends to server, decodes response.
        """
        import requests as req_lib

        # Build steganographic request
        stego_req = self.encoder.build_request(data)
        url = f"{self.server_url}{stego_req['path']}"

        # Add timing jitter (50-200ms) to avoid traffic analysis
        time.sleep(random.uniform(0.05, 0.2))

        try:
            if stego_req["method"] == "GET":
                resp = req_lib.get(
                    url,
                    headers=stego_req["headers"],
                    timeout=10,
                )
            else:
                resp = req_lib.post(
                    url,
                    headers=stego_req["headers"],
                    data=stego_req["body"],
                    timeout=10,
                )

            self.stats.bytes_sent += len(data)
            self.stats.requests_sent += 1

            # Decode response
            if resp.text:
                decoded = self.decoder.decode_from_json_body(resp.text)
                if decoded:
                    self.stats.bytes_received += len(decoded)
                    self.stats.requests_received += 1
                    return decoded

            return b""

        except Exception:
            return b""

    def start_proxy(self, local_port: int = 2222):
        """Start a local TCP proxy that bridges SSH through HTTP stego.

        Listens on local_port and forwards all traffic through the
        steganographic HTTP channel to the remote server.
        """
        self._running = True
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", local_port))
        server.listen(1)
        server.settimeout(1.0)

        print(f"[stego] Listening on 127.0.0.1:{local_port}")
        print(f"[stego] Forwarding through {self.server_url}")
        print(f"[stego] Connect: ssh -p {local_port} user@127.0.0.1")

        try:
            while self._running:
                try:
                    client, addr = server.accept()
                    print(f"[stego] Connection from {addr}")
                    t = threading.Thread(
                        target=self._handle_client,
                        args=(client,),
                        daemon=True,
                    )
                    t.start()
                except socket.timeout:
                    continue
        except KeyboardInterrupt:
            pass
        finally:
            self._running = False
            server.close()

    def _handle_client(self, client: socket.socket):
        """Handle a single proxied connection."""
        client.settimeout(1.0)
        try:
            while self._running:
                try:
                    data = client.recv(MAX_CHUNK_SIZE)
                    if not data:
                        break
                    response = self.send(data)
                    if response:
                        client.sendall(response)
                except socket.timeout:
                    continue
        except (ConnectionError, OSError):
            pass
        finally:
            client.close()

    def stop(self):
        """Stop the proxy."""
        self._running = False


def demo_encode_decode():
    """Demonstrate encoding and decoding of steganographic data."""
    print("\n=== HTTP Steganography Demo ===\n")

    key = "test-key-12345"
    encoder = StegoEncoder(key)
    decoder = StegoDecoder(key)

    # Test data (simulating SSH protocol)
    test_data = b"SSH-2.0-OpenSSH_8.9\r\n"

    print(f"Original data: {test_data}")
    print(f"Original size: {len(test_data)} bytes\n")

    # Encode as GET request
    get_req = encoder.build_request(test_data, method="GET")
    print("--- GET Request (data in cookies + query) ---")
    print(f"  Path: {get_req['path'][:80]}...")
    print(f"  Cookie: {get_req['headers'].get('Cookie', '')[:80]}...")
    print(f"  User-Agent: {get_req['headers']['User-Agent'][:60]}...")

    # Decode from GET
    decoded = decoder.decode_request(
        "GET", get_req["path"], get_req["headers"], None
    )
    print(f"  Decoded: {decoded}")
    print(f"  Match: {decoded == test_data}\n")

    # Encode as POST request
    post_req = encoder.build_request(test_data, method="POST")
    print("--- POST Request (data in JSON body) ---")
    body_preview = post_req["body"][:200] if post_req["body"] else "N/A"
    print(f"  Body: {body_preview}...")

    # Decode from POST
    decoded = decoder.decode_request(
        "POST", post_req["path"], post_req["headers"], post_req["body"]
    )
    print(f"  Decoded: {decoded}")
    print(f"  Match: {decoded == test_data}\n")

    # Larger payload test
    large_data = os.urandom(512)
    post_req = encoder.build_request(large_data, method="POST")
    decoded = decoder.decode_request(
        "POST", post_req["path"], post_req["headers"], post_req["body"]
    )
    print(f"--- Large payload test (512 bytes random) ---")
    print(f"  Encoded body size: {len(post_req['body'] or '')} bytes")
    print(f"  Decoded match: {decoded == large_data}")
    print(f"  Overhead: {len(post_req['body'] or '') / 512:.1f}x\n")
