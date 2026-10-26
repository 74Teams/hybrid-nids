FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    hping3 \
    hydra \
    curl \
    ftp \
    netcat-openbsd \
    iputils-ping \
    dnsutils \
    snmp \
    sqlmap \
    nikto \
    masscan \
    python3-scapy \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

RUN echo 'echo "Target: 172.28.0.50"' >> /root/.bashrc

WORKDIR /app
