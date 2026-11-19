# Honeypot SSH và HTTP: cùng một image, compose đổi tham số dòng lệnh để chạy `ssh` hoặc `http`.
# Build từ gốc repo: docker build -f services/honeypot/Dockerfile .
FROM python:3.10-slim

WORKDIR /app

COPY common/core/requirements.txt common/core/requirements.txt
COPY services/honeypot/requirements.txt services/honeypot/requirements.txt
RUN pip install --no-cache-dir -r services/honeypot/requirements.txt

COPY common/core/src common/core/src
COPY services/honeypot/src services/honeypot/src
COPY common/config common/config

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/common/core/src:/app/services/honeypot/src

CMD ["python", "-u", "-m", "nids.honeypot", "ssh"]
