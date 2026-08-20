# Project Sentinel - Multi-stage Docker Build
# Enterprise-grade Wireless Intrusion Detection System

# Stage 1: Build C extension for native frame decoding
FROM python:3.11-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy and compile C extension
COPY backend_server/native_frame_decoder.c .
RUN gcc -O3 -shared -fPIC -o libframe_decoder.so native_frame_decoder.c || echo "C extension build skipped"

# Stage 2: Python dependencies
FROM python:3.11-slim as python-deps

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Stage 3: Frontend build
FROM node:20-alpine as frontend-builder

WORKDIR /app/sentinel-ui

COPY sentinel-ui/package*.json ./
RUN npm ci

COPY sentinel-ui/ ./
RUN npm run build

# Stage 4: Runtime image
FROM python:3.11-slim as runtime

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 sentinel && chown -R sentinel:sentinel /app

# Copy C extension from builder
COPY --from=builder libframe_decoder.so ./backend_server/ || echo "C extension not available"

# Copy Python dependencies
COPY --from=python-deps /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=python-deps /usr/local/bin /usr/local/bin

# Copy application code
COPY --chown=sentinel:sentinel backend_server/ ./backend_server/
COPY --chown=sentinel:sentinel requirements.txt .

# Copy built frontend
COPY --from=frontend-builder --chown=sentinel:sentinel /app/sentinel-ui/dist ./static/

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SENTINEL_ENV=production \
    SENTINEL_MAX_DASHBOARD=50 \
    SENTINEL_MAX_ESP32=10

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

USER sentinel

EXPOSE 8000

CMD ["uvicorn", "backend_server.main:app", "--host", "0.0.0.0", "--port", "8000"]
