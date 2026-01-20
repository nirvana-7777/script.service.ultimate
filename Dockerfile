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
    # IMPORTANT: Set PYTHONPATH to include both lib and app directories
    PYTHONPATH=/app/lib:/app \
    DRM_PLUGINS_PATH=/drm-plugins

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

# Create directories for new structure
RUN mkdir -p /config /logs /cache /drm-plugins /app/routes && \
    chown -R ${USER_ID}:${GROUP_ID} /config /logs /cache /drm-plugins /app/routes

# Copy application code with new structure
COPY --chown=${USER_ID}:${GROUP_ID} service.py .
# IMPORTANT: Copy the entire routes directory
COPY --chown=${USER_ID}:${GROUP_ID} routes/ /app/routes/

# Create the directory structure for DRM plugins
RUN mkdir -p /app/lib/streaming_providers/base/drm/plugins && \
    chown -R ${USER_ID}:${GROUP_ID} /app/lib/streaming_providers/base/drm

# Quick directory check (for debugging)
RUN echo "=== Directory structure ===" && \
    ls -la /app && \
    echo "---" && \
    ls -la /app/routes/ 2>/dev/null || echo "routes directory not found" && \
    echo "---" && \
    ls -la /app/lib/ 2>/dev/null || echo "lib directory not found"

# Copy updated entrypoint script
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

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

# Entrypoint with wrapper script
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["python", "service.py", "--standalone", "--config-dir", "/config"]