"""WebSocket tunnel (wstunnel) configuration generator.

Generates wstunnel server and client configurations for tunneling
SSH through WebSocket connections over TLS.
"""

from dataclasses import dataclass


@dataclass
class WstunnelConfig:
    """Generated wstunnel configuration."""

    server_command: str
    client_command: str
    nginx_conf: str
    description: str
    ssh_command: str


class WstunnelGenerator:
    """Generates wstunnel configuration for SSH-over-WebSocket."""

    def __init__(self, target: str, domain: str | None = None,
                 ssh_port: int = 22, ws_port: int = 443,
                 ws_path: str = "/ws", user: str = "root"):
        self.target = target
        self.domain = domain or target
        self.ssh_port = ssh_port
        self.ws_port = ws_port
        self.ws_path = ws_path
        self.user = user

    def generate(self) -> WstunnelConfig:
        """Generate wstunnel server/client commands and nginx config."""
        server_command = (
            f"wstunnel server "
            f"ws://0.0.0.0:8080 "
            f"--restrict-to 127.0.0.1:{self.ssh_port}"
        )

        client_command = (
            f"wstunnel client "
            f"--local-to-remote 'tcp://2222:127.0.0.1:{self.ssh_port}' "
            f"wss://{self.domain}{self.ws_path}"
        )

        nginx_conf = f"""\
# Nginx reverse proxy for wstunnel
# Place in /etc/nginx/sites-available/wstunnel

server {{
    listen {self.ws_port} ssl;
    server_name {self.domain};

    ssl_certificate /etc/letsencrypt/live/{self.domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{self.domain}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    # WebSocket tunnel endpoint
    location {self.ws_path} {{
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 86400;
    }}

    # Serve a decoy website on other paths
    location / {{
        root /var/www/html;
        index index.html;
    }}
}}
"""

        ssh_command = (
            f"ssh -o ProxyCommand='wstunnel client -L stdio:%h:%p "
            f"wss://{self.domain}{self.ws_path}' "
            f"{self.user}@127.0.0.1"
        )

        return WstunnelConfig(
            server_command=server_command,
            client_command=client_command,
            nginx_conf=nginx_conf,
            description=(
                f"wstunnel encapsulates SSH in WebSocket frames over TLS. "
                f"Traffic appears as a standard HTTPS WebSocket connection. "
                f"Nginx serves as reverse proxy with a decoy website on "
                f"{self.domain}. Client connects via wss:// to "
                f"{self.domain}{self.ws_path}."
            ),
            ssh_command=ssh_command,
        )

    def generate_docker_compose(self) -> str:
        """Generate docker-compose.yml for wstunnel setup."""
        return f"""\
version: '3.8'

services:
  nginx:
    image: nginx:alpine
    ports:
      - "{self.ws_port}:{self.ws_port}"
    volumes:
      - ./nginx.conf:/etc/nginx/conf.d/default.conf
      - ./certs:/etc/letsencrypt/live/{self.domain}
      - ./www:/var/www/html
    depends_on:
      - wstunnel
    restart: unless-stopped

  wstunnel:
    image: erebe/wstunnel
    command: >
      server ws://0.0.0.0:8080
      --restrict-to openssh:{self.ssh_port}
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
    volumes:
      - ./ssh_config:/config
    restart: unless-stopped
"""
