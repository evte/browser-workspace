ARG PYTHON_BASE=python:3.12-slim-bookworm
FROM ${PYTHON_BASE}
RUN apt-get update && apt-get install -y --no-install-recommends chromium xvfb x11vnc websockify novnc fonts-noto-cjk fonts-liberation ca-certificates && rm -rf /var/lib/apt/lists/*
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 util-linux && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt && useradd --create-home --uid 10001 browser && mkdir -p /data
COPY backend /app/backend
COPY frontend /app/frontend
ENV DATA_DIR=/data
EXPOSE 8000
CMD ["uvicorn", "backend.app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
