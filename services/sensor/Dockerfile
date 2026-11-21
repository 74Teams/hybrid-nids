# Sensor: bắt gói, rule, flow, ngưỡng bất thường.
# Rule, mô hình và cấu hình được gắn vào lúc chạy (xem docker-compose.yml).
# Build từ gốc repo: docker build -f services/sensor/Dockerfile .
# scikit-learn 1.9.1 (bản đã học mô hình) cần Python 3.11+
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    tcpdump \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY common/core/requirements.txt common/core/requirements.txt
COPY services/sensor/requirements.txt services/sensor/requirements.txt
RUN pip install --no-cache-dir -r services/sensor/requirements.txt

COPY common/core/src common/core/src
COPY services/sensor/src services/sensor/src
COPY common/config common/config

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/common/core/src:/app/services/sensor/src

CMD ["python", "-u", "-m", "nids.engine"]
