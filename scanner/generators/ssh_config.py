"""SSH client configuration generator.

Generates ~/.ssh/config entries with appropriate ProxyCommand
directives for each covert SSH technique.
"""

from dataclasses import dataclass

from scanner.engine.scorer import TechniqueID


@dataclass
class SSHClientConfig:
    """Generated SSH client configuration."""

    config_entry: str
    description: str
    direct_command: str


class SSHConfigGenerator:
    """Generates SSH client configuration for covert techniques."""

    def __init__(self, target: str, domain: str | None = None,
                 user: str = "root"):
        self.target = target
        self.domain = domain or target
        self.user = user

    def generate(self, technique: TechniqueID) -> SSHClientConfig:
        """Generate SSH config entry for the specified technique."""
        generators = {
            TechniqueID.DIRECT_SSH: self._direct,
            TechniqueID.STUNNEL_SSLH: self._stunnel_sslh,
            TechniqueID.WEBSOCKET_TLS: self._websocket,
            TechniqueID.OBFS4: self._obfs4,
            TechniqueID.DNS_TUNNEL: self._dns_tunnel,
            TechniqueID.ICMP_TUNNEL: self._icmp_tunnel,
            TechniqueID.TOR: self._tor,
            TechniqueID.SHADOWSOCKS: self._shadowsocks,
        }
        gen = generators.get(technique, self._direct)
        return gen()

    def _direct(self) -> SSHClientConfig:
        return SSHClientConfig(
            config_entry=f"""\
Host covert-direct
    HostName {self.target}
    User {self.user}
    Port 22
""",
            description="Direct SSH connection (no tunneling).",
            direct_command=f"ssh {self.user}@{self.target}",
        )

    def _stunnel_sslh(self) -> SSHClientConfig:
        return SSHClientConfig(
            config_entry=f"""\
Host covert-stunnel
    HostName {self.target}
    User {self.user}
    Port 443
    # Alternative: use openssl s_client as ProxyCommand
    # ProxyCommand openssl s_client -quiet -connect {self.target}:443
""",
            description=(
                "SSH via SSLH on port 443. SSLH detects the SSH protocol "
                "and forwards it. Alternatively, use Stunnel with openssl "
                "s_client as ProxyCommand for TLS wrapping."
            ),
            direct_command=f"ssh -p 443 {self.user}@{self.target}",
        )

    def _websocket(self) -> SSHClientConfig:
        return SSHClientConfig(
            config_entry=f"""\
Host covert-ws
    HostName {self.target}
    User {self.user}
    ProxyCommand wstunnel client -L stdio:%h:%p wss://{self.domain}/ws
""",
            description=(
                "SSH tunneled through WebSocket over TLS. Requires wstunnel "
                "installed on the client. Traffic appears as HTTPS WebSocket."
            ),
            direct_command=(
                f"ssh -o ProxyCommand='wstunnel client -L stdio:%h:%p "
                f"wss://{self.domain}/ws' {self.user}@{self.target}"
            ),
        )

    def _obfs4(self) -> SSHClientConfig:
        return SSHClientConfig(
            config_entry=f"""\
Host covert-obfs4
    HostName 127.0.0.1
    User {self.user}
    Port 2222
    # Requires obfs4proxy running locally:
    # obfs4proxy -enableLogging -logLevel INFO
    # And SSH configured to forward through obfs4
    ProxyCommand obfs4proxy -transport obfs4 -connect {self.target}:443
""",
            description=(
                "SSH through obfs4 protocol obfuscation. Traffic is "
                "indistinguishable from random bytes. Best against DPI. "
                "Requires obfs4proxy on both client and server."
            ),
            direct_command=(
                f"# Start obfs4proxy client, then:\n"
                f"ssh -p 2222 {self.user}@127.0.0.1"
            ),
        )

    def _dns_tunnel(self) -> SSHClientConfig:
        return SSHClientConfig(
            config_entry=f"""\
Host covert-dns
    HostName 127.0.0.1
    User {self.user}
    Port 2222
    # Requires iodine or dnscat2 tunnel running:
    # iodine -f -r {self.domain} <nameserver>
    # Then SSH through the tunnel interface
""",
            description=(
                "SSH tunneled through DNS queries using iodine/dnscat2. "
                "Very slow (~50-150 Kbps) but works when only DNS is available. "
                "Requires a domain with NS records pointing to your server."
            ),
            direct_command=(
                f"# Start iodine: iodine -f -r {self.domain}\n"
                f"ssh {self.user}@10.0.0.1  # iodine tunnel IP"
            ),
        )

    def _icmp_tunnel(self) -> SSHClientConfig:
        return SSHClientConfig(
            config_entry=f"""\
Host covert-icmp
    HostName 127.0.0.1
    User {self.user}
    Port 2222
    # Requires icmptunnel or hans running:
    # hans -c {self.target} -p <password>
    # Then SSH through the tunnel interface
""",
            description=(
                "SSH tunneled through ICMP echo (ping) packets using "
                "hans or icmptunnel. Very slow but works when only ICMP "
                "is allowed. Requires root on both client and server."
            ),
            direct_command=(
                f"# Start hans: sudo hans -c {self.target} -p <password>\n"
                f"ssh {self.user}@10.0.0.1  # hans tunnel IP"
            ),
        )

    def _tor(self) -> SSHClientConfig:
        return SSHClientConfig(
            config_entry=f"""\
Host covert-tor
    HostName <your-onion-address>.onion
    User {self.user}
    ProxyCommand nc -X 5 -x 127.0.0.1:9050 %h %p
    # Requires Tor running locally: systemctl start tor
""",
            description=(
                "SSH via Tor Hidden Service (.onion). Provides strong "
                "anonymity but high latency (~500ms+). Requires Tor running "
                "on both client and server. Replace <your-onion-address> "
                "with the actual .onion from the server."
            ),
            direct_command=(
                f"ssh -o ProxyCommand='nc -X 5 -x 127.0.0.1:9050 %h %p' "
                f"{self.user}@<your-onion-address>.onion"
            ),
        )

    def _shadowsocks(self) -> SSHClientConfig:
        return SSHClientConfig(
            config_entry=f"""\
Host covert-ss
    HostName 127.0.0.1
    User {self.user}
    Port 2222
    # Requires Shadowsocks local client running:
    # ss-local -s {self.target} -p 443 -l 1080 -m aes-256-gcm -k <password>
    ProxyCommand nc -X 5 -x 127.0.0.1:1080 %h %p
""",
            description=(
                "SSH through Shadowsocks SOCKS5 proxy. Shadowsocks uses "
                "AEAD encryption that resists DPI. Requires Shadowsocks "
                "server on the target and ss-local on the client."
            ),
            direct_command=(
                f"ssh -o ProxyCommand='nc -X 5 -x 127.0.0.1:1080 %h %p' "
                f"{self.user}@{self.target}"
            ),
        )
