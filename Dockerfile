# Ultimate Backend Streaming Service - Kodi addon in standalone Docker mode
FROM python:3.11-slim

# Build arguments
ARG USER_ID=1000
ARG GROUP_ID=1000
ARG APP_USER=ultimate
ARG APP_HOME=/app

# Environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TZ=UTC \
    ULTIMATE_PORT=7777 \
    ULTIMATE_COUNTRY=DE \
    ULTIMATE_DEBUG=false \
    ULTIMATE_EPG_URL="https://example.com/epg.xml.gz" \
    PYTHONPATH=/app/lib

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libxml2-dev \
    libxslt-dev \
    libffi-dev \
    libssl-dev \
    libxmlsec1-dev \
    pkg-config \
    curl \
    ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR ${APP_HOME}

# Copy requirements.txt first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Create user
RUN groupadd -g ${GROUP_ID} ${APP_USER} && \
    useradd -u ${USER_ID} -g ${APP_USER} -m -s /bin/bash ${APP_USER}

# Copy application code
COPY --chown=${USER_ID}:${GROUP_ID} . .

# Quick directory check
RUN ls -la /app && echo "---" && ls -la /app/lib/ 2>/dev/null || echo "lib directory not found"

# Create directories
RUN mkdir -p /config /logs /cache && \
    chown -R ${USER_ID}:${GROUP_ID} /config /logs /cache

# Switch to non-root user
USER ${USER_ID}

# Create default config
RUN if [ ! -f /config/config.json ]; then \
    echo '{"default_country": "DE", "server_port": 7777, "debug_mode": false}' > /config/config.json; \
    fi

# Expose port
EXPOSE ${ULTIMATE_PORT}

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:${ULTIMATE_PORT}/api/providers || exit 1

# Labels
LABEL maintainer="nirvana-7777" \
      description="Ultimate Backend Streaming Service"

# Simple entrypoint
ENTRYPOINT ["python", "service.py"]
CMD ["--standalone", "--config-dir", "/config"]