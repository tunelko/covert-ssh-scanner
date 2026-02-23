"""Tor Hidden Service configuration generator.

Generates Tor and torrc configs to expose SSH as a .onion hidden service.
"""

from dataclasses import dataclass


@dataclass
class TorConfig:
    """Generated Tor Hidden Service configuration."""

    torrc: str
    client_torrc: str
    description: str
    ssh_command: str


class TorGenerator:
    """Generates Tor Hidden Service configuration for covert SSH access."""

    def __init__(self, target: str, ssh_port: int = 22,
                 hidden_port: int = 22, user: str = "root"):
        self.target = target
        self.ssh_port = ssh_port
        self.hidden_port = hidden_port
        self.user = user

    def generate(self) -> TorConfig:
        """Generate Tor hidden service server and client configurations."""
        torrc = f"""\
# Tor Hidden Service configuration for SSH
# Append to /etc/tor/torrc on the SERVER

# Hidden Service for SSH
HiddenServiceDir /var/lib/tor/ssh_hidden_service/
HiddenServicePort {self.hidden_port} 127.0.0.1:{self.ssh_port}

# Security hardening
HiddenServiceVersion 3
HiddenServiceSingleHopMode 0

# Optional: client authorization (v3 onion)
# HiddenServiceAuthorizeClient stealth client1

# After restarting Tor, the .onion address will be in:
# /var/lib/tor/ssh_hidden_service/hostname
"""

        client_torrc = """\
# Tor client configuration
# Append to /etc/tor/torrc on the CLIENT

# SOCKS proxy for SSH
SocksPort 9050

# Optional: use bridges if Tor is blocked
# UseBridges 1
# Bridge obfs4 <bridge-address>

# Optional: restrict to specific circuit
# MapAddress <onion-address> <onion-address>
"""

        ssh_command = (
            f"ssh -o ProxyCommand='nc -X 5 -x 127.0.0.1:9050 %h %p' "
            f"{self.user}@<your-onion-address>.onion"
        )

        return TorConfig(
            torrc=torrc,
            client_torrc=client_torrc,
            description=(
                f"Tor Hidden Service exposes SSH as a .onion address. "
                f"Traffic is routed through the Tor network with end-to-end "
                f"encryption. No ports need to be opened on the server's "
                f"firewall. The client connects via the Tor SOCKS proxy. "
                f"Latency is high (~500ms+) but provides strong anonymity. "
                f"After starting Tor on the server, find your .onion address "
                f"in /var/lib/tor/ssh_hidden_service/hostname."
            ),
            ssh_command=ssh_command,
        )

    def generate_docker_compose(self) -> str:
        """Generate docker-compose.yml for Tor hidden service."""
        return f"""\
version: '3.8'

services:
  tor:
    image: osminogin/tor-simple
    volumes:
      - ./torrc:/etc/tor/torrc
      - tor_data:/var/lib/tor
    depends_on:
      - openssh
    restart: unless-stopped

  openssh:
    image: linuxserver/openssh-server
    environment:
      - PUID=1000
      - PGID=1000
      - PASSWORD_ACCESS=true
      - USER_NAME={self.user}
    restart: unless-stopped

volumes:
  tor_data:
"""
