# Multi-stage build for ghmon-cli
FROM python:3.11-slim as builder

# Set working directory
WORKDIR /app

# Install system dependencies for building
RUN apt-get update && apt-get install -y \
    git \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Install TruffleHog
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

# Copy requirements and install Python dependencies
COPY pyproject.toml ./
RUN pip install --no-cache-dir build && \
    pip install --no-cache-dir .

# Production stage
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy TruffleHog from builder stage
COPY --from=builder /usr/local/bin/trufflehog /usr/local/bin/trufflehog

# Copy Python packages from builder stage
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin/ghmon-cli /usr/local/bin/ghmon-cli

# Copy application code
COPY ghmon_cli/ ./ghmon_cli/
COPY ghmon_config.yaml.example ./

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash ghmon && \
    chown -R ghmon:ghmon /app

# Switch to non-root user
USER ghmon

# Create directories for data persistence
RUN mkdir -p /app/data /app/logs

# Set environment variables
ENV PYTHONPATH=/app
ENV GHMON_CONFIG_PATH=/app/ghmon_config.yaml
ENV GHMON_DATA_DIR=/app/data
ENV GHMON_LOG_DIR=/app/logs

# Expose volume for configuration and data
VOLUME ["/app/data", "/app/logs", "/app/config"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -m ghmon_cli --version || exit 1

# Default command
CMD ["python", "-m", "ghmon_cli", "--help"]
