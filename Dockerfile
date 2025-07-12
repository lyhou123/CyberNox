# CyberNox - Advanced Cybersecurity Toolkit
# Multi-stage Docker build for production deployment

# Stage 1: Base image with system dependencies
FROM python:3.11-slim as base

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    TZ=UTC

# Install system dependencies and security tools
RUN apt-get update && apt-get install -y \
    # Build dependencies
    gcc \
    g++ \
    make \
    pkg-config \
    # Network tools
    nmap \
    netcat-traditional \
    dnsutils \
    whois \
    curl \
    wget \
    # System utilities
    procps \
    htop \
    nano \
    git \
    # Security libraries
    libpcap-dev \
    libssl-dev \
    libffi-dev \
    # Cleanup
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Stage 2: Python dependencies
FROM base as dependencies

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Install additional security-focused packages
RUN pip install --no-cache-dir \
    scapy \
    psutil \
    flask \
    flask-cors \
    flask-limiter \
    pyyaml \
    dnspython \
    beautifulsoup4 \
    requests \
    click \
    colorama

# Stage 3: Production image
FROM dependencies as production

# Create non-root user for security
RUN groupadd -r cybernox && useradd -r -g cybernox -s /bin/bash cybernox

# Set working directory
WORKDIR /app

# Copy application code
COPY --chown=cybernox:cybernox . .

# Create necessary directories
RUN mkdir -p /app/data/wordlists \
             /app/reports \
             /app/logs \
             /app/config \
    && chown -R cybernox:cybernox /app

# Set up configuration
RUN cp config.yml /app/config/config.yml || echo "Config file not found, will use defaults"

# Expose ports
EXPOSE 5000 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/api/v1/status || exit 1

# Switch to non-root user
USER cybernox

# Set entrypoint
ENTRYPOINT ["python", "main.py"]
CMD ["serve", "--host", "0.0.0.0", "--port", "5000"]

# Development stage
FROM dependencies as development

# Install development dependencies
RUN pip install --no-cache-dir \
    pytest \
    black \
    flake8 \
    mypy

# Create cybernox user for development
RUN groupadd -r cybernox && useradd -r -g cybernox -s /bin/bash cybernox

WORKDIR /app
COPY --chown=cybernox:cybernox . .

# Create directories
RUN mkdir -p /app/data/wordlists \
             /app/reports \
             /app/logs \
             /app/config \
    && chown -R cybernox:cybernox /app

USER cybernox

# Development command
CMD ["python", "main.py", "serve", "--host", "0.0.0.0", "--port", "5000"]
