"""SSLH configuration generator.

Generates SSLH multiplexer configs that share port 443 between
SSH, HTTPS, and other protocols based on protocol detection.
"""

from dataclasses import dataclass


@dataclass
class SSLHConfig:
    """Generated SSLH configuration."""

    config_file: str
    systemd_override: str
    description: str
    ssh_command: str


class SSLHGenerator:
    """Generates SSLH configuration for protocol multiplexing on port 443."""

    def __init__(self, target: str, listen_port: int = 443,
                 ssh_port: int = 22, https_port: int = 8443,
                 user: str = "root"):
        self.target = target
        self.listen_port = listen_port
        self.ssh_port = ssh_port
        self.https_port = https_port
        self.user = user

    def generate(self) -> SSLHConfig:
        """Generate SSLH configuration files."""
        config_file = f"""\
# SSLH configuration file
# /etc/sslh/sslh.cfg
#
# Multiplexes SSH + HTTPS on port {self.listen_port}
# SSLH detects the protocol from the first bytes of the connection

verbose: false;
foreground: true;
inetd: false;
numeric: false;
transparent: false;
timeout: 5;

listen:
(
    {{ host: "0.0.0.0"; port: "{self.listen_port}"; }}
);

protocols:
(
    # SSH detection (client sends "SSH-" banner)
    {{ name: "ssh"; service: "ssh"; host: "127.0.0.1"; port: "{self.ssh_port}"; }},

    # OpenVPN detection (if needed)
    # {{ name: "openvpn"; host: "127.0.0.1"; port: "1194"; }},

    # HTTPS fallback (anything that looks like TLS)
    {{ name: "tls"; host: "127.0.0.1"; port: "{self.https_port}"; }},

    # Default fallback for anything else
    {{ name: "anyprot"; host: "127.0.0.1"; port: "{self.https_port}"; }}
);
"""

        systemd_override = f"""\
# Systemd override for SSLH
# Place in /etc/systemd/system/sslh.service.d/override.conf

[Service]
ExecStart=
ExecStart=/usr/sbin/sslh --foreground \\
    --listen 0.0.0.0:{self.listen_port} \\
    --ssh 127.0.0.1:{self.ssh_port} \\
    --tls 127.0.0.1:{self.https_port}
KillMode=process
"""

        ssh_command = f"ssh -p {self.listen_port} {self.user}@{self.target}"

        return SSLHConfig(
            config_file=config_file,
            systemd_override=systemd_override,
            description=(
                f"SSLH multiplexes SSH and HTTPS on port {self.listen_port}. "
                f"It detects the protocol from the first bytes: SSH clients "
                f"send 'SSH-2.0-...' banner, TLS clients send ClientHello. "
                f"SSH traffic is forwarded to :{self.ssh_port}, HTTPS to "
                f":{self.https_port}. From the network, all traffic goes to "
                f"port {self.listen_port} making SSH indistinguishable at the "
                f"port level. NOTE: DPI can still detect SSH protocol inside."
            ),
            ssh_command=ssh_command,
        )

    def generate_docker_compose(self) -> str:
        """Generate docker-compose.yml for SSLH setup."""
        return f"""\
version: '3.8'

services:
  sslh:
    image: sslh:latest
    ports:
      - "{self.listen_port}:{self.listen_port}"
    command: >
      --foreground
      --listen 0.0.0.0:{self.listen_port}
      --ssh openssh:{self.ssh_port}
      --tls nginx:{self.https_port}
    depends_on:
      - openssh
      - nginx
    restart: unless-stopped

  openssh:
    image: linuxserver/openssh-server
    environment:
      - PUID=1000
      - PGID=1000
      - PASSWORD_ACCESS=true
      - USER_NAME={self.user}
    restart: unless-stopped

  nginx:
    image: nginx:alpine
    volumes:
      - ./www:/var/www/html
      - ./certs:/etc/ssl/certs
    restart: unless-stopped
"""
