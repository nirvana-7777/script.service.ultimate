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
    PYTHONPATH=/app/lib:/app \
    DRM_PLUGINS_PATH=/drm-plugins \
    M3U_PLAYLISTS_PATH=/playlists \
    SCRIPTS_PROVIDERS_PATH=/playlists

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

# Create directories for new structure (including routes/streams)
RUN mkdir -p /config /logs /cache /drm-plugins /playlists /scripts && \
    mkdir -p /app/routes /app/routes/streams /app/lib && \
    chown -R ${USER_ID}:${GROUP_ID} /config /logs /cache /drm-plugins /playlists /scripts /app

# CRITICAL FIX: Copy the lib directory containing streaming_providers
COPY --chown=${USER_ID}:${GROUP_ID} lib/ /app/lib/

# Copy application code with new structure
COPY --chown=${USER_ID}:${GROUP_ID} service.py .

# Copy the entire routes directory (including streams subdirectory)
COPY --chown=${USER_ID}:${GROUP_ID} routes/ /app/routes/

# Copy resources directory (for web UI)
COPY --chown=${USER_ID}:${GROUP_ID} resources/ /app/resources/

# Create the directory structure for DRM plugins
RUN mkdir -p /app/lib/streaming_providers/base/drm/plugins && \
    chown -R ${USER_ID}:${GROUP_ID} /app/lib/streaming_providers/base/drm

# Verify directory structure (for debugging)
RUN echo "=== Directory structure ===" && \
    ls -la /app && \
    echo "--- routes ---" && \
    ls -la /app/routes/ 2>/dev/null || echo "ERROR: routes directory not found" && \
    echo "--- routes/streams ---" && \
    ls -la /app/routes/streams/ 2>/dev/null || echo "ERROR: routes/streams directory not found" && \
    echo "--- lib ---" && \
    ls -la /app/lib/ 2>/dev/null || echo "ERROR: lib directory not found" && \
    echo "--- streaming_providers ---" && \
    ls -la /app/lib/streaming_providers/ 2>/dev/null || echo "ERROR: streaming_providers not found"

# Validate critical split structure files exist
RUN echo "=== Validating split structure ===" && \
    test -f /app/routes/__init__.py && echo "✓ routes/__init__.py" || (echo "✗ MISSING: routes/__init__.py" && exit 1) && \
    test -f /app/routes/streams/__init__.py && echo "✓ routes/streams/__init__.py" || (echo "✗ MISSING: routes/streams/__init__.py" && exit 1) && \
    test -f /app/routes/streams/channels.py && echo "✓ routes/streams/channels.py" || (echo "✗ MISSING: routes/streams/channels.py" && exit 1) && \
    test -f /app/routes/streams/events.py && echo "✓ routes/streams/events.py" || (echo "✗ MISSING: routes/streams/events.py" && exit 1) && \
    test -f /app/routes/streams/vod.py && echo "✓ routes/streams/vod.py" || (echo "✗ MISSING: routes/streams/vod.py" && exit 1) && \
    test -f /app/routes/streams/recordings.py && echo "✓ routes/streams/recordings.py" || (echo "✗ MISSING: routes/streams/recordings.py" && exit 1) && \
    test -f /app/routes/streams/epg.py && echo "✓ routes/streams/epg.py" || (echo "✗ MISSING: routes/streams/epg.py" && exit 1) && \
    test -f /app/service.py && echo "✓ service.py" || (echo "✗ MISSING: service.py" && exit 1) && \
    echo "✓ All split structure files validated successfully!"

# Copy entrypoint script
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
      description="Ultimate Backend Streaming Service with split route modules" \
      version="2.0"

# Entrypoint with wrapper script
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["python", "service.py", "--standalone", "--config-dir", "/config"]