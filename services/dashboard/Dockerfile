# Dashboard và API (FastAPI).
# Build từ gốc repo: docker build -f services/dashboard/Dockerfile .
FROM python:3.10-slim

WORKDIR /app

COPY common/core/requirements.txt common/core/requirements.txt
COPY services/dashboard/requirements.txt services/dashboard/requirements.txt
RUN pip install --no-cache-dir -r services/dashboard/requirements.txt

COPY common/core/src common/core/src
COPY services/dashboard/src services/dashboard/src
# Trang Rules kiểm tra custom.rules bằng bộ phân tích rule của sensor (chỉ các module thuần Python, không cần scapy)
COPY services/sensor/src services/sensor/src
COPY common/config common/config

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/common/core/src:/app/services/dashboard/src:/app/services/sensor/src

CMD ["uvicorn", "nids.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
