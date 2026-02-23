FROM python:3.12-slim

LABEL maintainer="tunelko"
LABEL description="Covert SSH Scanner - Intelligent covert channel detection"

# System deps for scapy (raw sockets, tcpdump for packet capture)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        iputils-ping \
        tcpdump \
        libpcap-dev \
        net-tools \
        dnsutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Python deps primero (layer caching: solo se reinstalan si cambia requirements.txt)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Source code (cambios aqui no reinstalan deps)
COPY . .

# Output directory (mount as volume to persist results)
RUN mkdir -p /app/output
VOLUME /app/output

ENTRYPOINT ["python", "-m", "scanner"]
