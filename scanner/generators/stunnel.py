"""Stunnel configuration generator.

Generates server and client stunnel configs for wrapping SSH in TLS,
typically combined with SSLH for multiplexing on port 443.
"""

from dataclasses import dataclass


@dataclass
class StunnelConfig:
    """Generated Stunnel configuration files."""

    server_conf: str
    client_conf: str
    description: str
    ssh_command: str


class StunnelGenerator:
    """Generates Stunnel + SSLH configuration for SSH-over-TLS."""

    def __init__(self, target: str, ssh_port: int = 22,
                 listen_port: int = 443, user: str = "root"):
        self.target = target
        self.ssh_port = ssh_port
        self.listen_port = listen_port
        self.user = user

    def generate(self) -> StunnelConfig:
        """Generate Stunnel server and client configurations."""
        server_conf = f"""\
; Stunnel server configuration
; Wraps SSH in TLS on port {self.listen_port}
; Combine with SSLH for HTTPS multiplexing

pid = /var/run/stunnel4/stunnel.pid
setuid = stunnel4
setgid = stunnel4

[ssh-over-tls]
accept = 0.0.0.0:{self.listen_port}
connect = 127.0.0.1:{self.ssh_port}
cert = /etc/stunnel/stunnel.pem
key = /etc/stunnel/stunnel.key

; TLS settings for maximum compatibility
sslVersion = TLSv1.2
ciphers = ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256
"""

        client_conf = f"""\
; Stunnel client configuration
; Connects to remote Stunnel server and exposes local SSH port

pid = /var/run/stunnel4/stunnel-client.pid

[ssh-tunnel]
client = yes
accept = 127.0.0.1:2222
connect = {self.target}:{self.listen_port}

; Verify server certificate (optional, set to 0 for self-signed)
verifyChain = no
"""

        ssh_command = (
            f"ssh -o ProxyCommand='openssl s_client -quiet -connect "
            f"{self.target}:{self.listen_port}' {self.user}@{self.target}"
        )

        return StunnelConfig(
            server_conf=server_conf,
            client_conf=client_conf,
            description=(
                f"Stunnel wraps SSH traffic in TLS on port {self.listen_port}. "
                f"Traffic appears as standard HTTPS to network observers. "
                f"Server: install stunnel4, place config in /etc/stunnel/. "
                f"Client: connect via local port 2222 or use ProxyCommand."
            ),
            ssh_command=ssh_command,
        )

    def generate_sslh_config(self) -> str:
        """Generate SSLH config for multiplexing HTTPS and SSH on port 443."""
        return f"""\
# SSLH configuration — multiplex HTTPS + SSH on port 443
# /etc/default/sslh

RUN=yes
DAEMON=/usr/sbin/sslh
DAEMON_OPTS="--user sslh \\
  --listen 0.0.0.0:{self.listen_port} \\
  --ssh 127.0.0.1:{self.ssh_port} \\
  --ssl 127.0.0.1:8443 \\
  --pidfile /var/run/sslh/sslh.pid"
"""

    def generate_docker_compose(self) -> str:
        """Generate docker-compose.yml for Stunnel + SSLH setup."""
        return f"""\
version: '3.8'

services:
  sslh:
    image: sslh:latest
    ports:
      - "{self.listen_port}:{self.listen_port}"
    command: >
      --listen 0.0.0.0:{self.listen_port}
      --ssh openssh:{self.ssh_port}
      --ssl stunnel:8443
    depends_on:
      - openssh
      - stunnel
    restart: unless-stopped

  stunnel:
    image: stunnel:latest
    volumes:
      - ./stunnel.conf:/etc/stunnel/stunnel.conf
      - ./certs:/etc/stunnel/certs
    restart: unless-stopped

  openssh:
    image: linuxserver/openssh-server
    environment:
      - PUID=1000
      - PGID=1000
      - PASSWORD_ACCESS=true
      - USER_NAME={self.user}
    volumes:
      - ./ssh_config:/config
    restart: unless-stopped
"""
