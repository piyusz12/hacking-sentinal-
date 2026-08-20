# Sentinel DevSecOps Platform - Multi-Stage Dockerfile
# Optimized for security, size, and build performance

# ===========================================
# Stage 1: Build C Extension (Native Frame Decoder)
# ===========================================
FROM python:3.11-slim as c-builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy C source file
COPY backend_server/native_frame_decoder.c .

# Compile the C extension
RUN gcc -O3 -fPIC -shared -o libnative_decoder.so native_frame_decoder.c

# ===========================================
# Stage 2: Install Python Dependencies
# ===========================================
FROM python:3.11-slim as python-builder

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# ===========================================
# Stage 3: Build Frontend (React/Vite)
# ===========================================
FROM node:20-alpine as frontend-builder

WORKDIR /frontend

# Copy package files
COPY sentinel-ui/package*.json ./

# Install dependencies
RUN npm ci

# Copy source code
COPY sentinel-ui/ .

# Build for production
RUN npm run build

# ===========================================
# Stage 4: Runtime Image
# ===========================================
FROM python:3.11-slim as runtime

# Create non-root user for security
RUN groupadd --gid 1000 sentinel && \
    useradd --uid 1000 --gid sentinel --shell /bin/bash --create-home sentinel

WORKDIR /app

# Copy compiled C extension from builder
COPY --from=c-builder /build/libnative_decoder.so /app/backend_server/

# Copy Python dependencies from builder
COPY --from=python-builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=python-builder /usr/local/bin /usr/local/bin

# Copy backend code
COPY backend_server/ ./backend_server/
COPY tests/ ./tests/
COPY run_backend.py .

# Copy built frontend from builder
COPY --from=frontend-builder /frontend/dist ./static/

# Copy configuration
COPY .env.example .env.template

# Create logs directory
RUN mkdir -p /app/logs && chown -R sentinel:sentinel /app

# Switch to non-root user
USER sentinel

# Expose ports
EXPOSE 8000 9090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Set entrypoint
ENTRYPOINT ["python", "-m", "uvicorn", "backend_server.main:app", "--host", "0.0.0.0", "--port", "8000"]
