# Bộ chuyển hướng IP đáng ngờ sang honeypot bằng iptables (cần quyền NET_ADMIN lúc chạy).
# Build từ gốc repo: docker build -f services/redirector/Dockerfile .
FROM python:3.10-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY common/core/requirements.txt common/core/requirements.txt
COPY services/redirector/requirements.txt services/redirector/requirements.txt
RUN pip install --no-cache-dir -r services/redirector/requirements.txt

COPY common/core/src common/core/src
COPY services/redirector/src services/redirector/src
COPY common/config common/config

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/common/core/src:/app/services/redirector/src

CMD ["python", "-u", "-m", "nids.redirector"]
