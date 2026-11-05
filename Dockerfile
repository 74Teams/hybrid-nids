FROM python:3.10-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    tcpdump \
    gcc \
    curl \
    iptables \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED=1

CMD ["python", "-u", "-m", "nids.engine"]