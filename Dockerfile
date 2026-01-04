# Base image
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY requirement.txt .
RUN pip install --no-cache-dir -r requirement.txt

# ✅ COPY CONFIG FILES
COPY config.yaml ./
COPY .env ./

# ✅ COPY APP FILES
COPY src/ ./src
COPY sample_logs/ ./sample_logs/
COPY tests/ ./tests

CMD ["uvicorn", "src.api:app", "--host", "0.0.0.0", "--port", "80"]
