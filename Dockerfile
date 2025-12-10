# Ultimate Backend Streaming Service - Kodi addon in standalone Docker mode
FROM python:3.11-slim

# Build arguments for user/group configuration
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
    PYTHONPATH=${APP_HOME}/lib:$PYTHONPATH \
    HOME=/home/${APP_USER} \
    PATH=/home/${APP_USER}/.local/bin:$PATH

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
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Create application user and group with configurable UID/GID
RUN groupadd -g ${GROUP_ID} ${APP_USER} && \
    useradd -u ${USER_ID} -g ${APP_USER} -m -s /bin/bash ${APP_USER}

# Set working directory
WORKDIR ${APP_HOME}

# Copy requirements first for better caching
COPY requirements.txt /tmp/requirements.txt

# Install Python dependencies
# If requirements.txt exists, use it. Otherwise install defaults.
RUN if [ -f /tmp/requirements.txt ]; then \
        echo "Installing from requirements.txt..." && \
        pip install --no-cache-dir --upgrade pip && \
        pip install --no-cache-dir -r /tmp/requirements.txt; \
    else \
        echo "No requirements.txt found, installing default packages..." && \
        pip install --no-cache-dir --upgrade pip && \
        pip install --no-cache-dir \
            bottle>=0.12.25 \
            requests>=2.31.0 \
            lxml>=4.9.3 \
            defusedxml>=0.7.1 \
            m3u8>=4.0.0 \
            iso8601>=1.1.0 \
            pycountry>=23.12.11 \
            python-dateutil>=2.8.2 \
            urllib3>=2.0.7 \
            chardet>=5.2.0 \
            pycryptodome>=3.19.0 \
            cryptography>=41.0.0; \
    fi

# Copy application code
COPY --chown=${USER_ID}:${GROUP_ID} . ${APP_HOME}/

# Create necessary directories
RUN mkdir -p /config /logs /cache && \
    chown -R ${USER_ID}:${GROUP_ID} /config /logs /cache

# Create a requirements.txt if it doesn't exist (for documentation)
RUN if [ ! -f requirements.txt ]; then \
    echo "# Ultimate Backend Service Requirements" > requirements.txt && \
    echo "# Auto-generated for documentation" >> requirements.txt && \
    echo "" >> requirements.txt && \
    echo "bottle>=0.12.25" >> requirements.txt && \
    echo "requests>=2.31.0" >> requirements.txt && \
    echo "lxml>=4.9.3" >> requirements.txt && \
    echo "defusedxml>=0.7.1" >> requirements.txt && \
    echo "m3u8>=4.0.0" >> requirements.txt && \
    echo "iso8601>=1.1.0" >> requirements.txt && \
    echo "pycountry>=23.12.11" >> requirements.txt && \
    echo "python-dateutil>=2.8.2" >> requirements.txt && \
    echo "urllib3>=2.0.7" >> requirements.txt && \
    echo "chardet>=5.2.0" >> requirements.txt && \
    echo "pycryptodome>=3.19.0" >> requirements.txt && \
    echo "cryptography>=41.0.0" >> requirements.txt; \
    fi

# Switch to non-root user
USER ${USER_ID}

# Create default config if not provided
RUN if [ ! -f /config/config.json ]; then \
    echo '{"default_country": "DE", "server_port": 7777, "debug_mode": false}' > /config/config.json; \
    fi

# Expose the service port
EXPOSE ${ULTIMATE_PORT}

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:${ULTIMATE_PORT}/api/providers || exit 1

# Labels for better image metadata
LABEL maintainer="nirvana-7777" \
      description="Ultimate Backend Streaming Service" \
      version="1.0.0" \
      org.opencontainers.image.source="https://github.com/nirvana-7777/script.service.ultimate"

# Run in standalone mode (since Kodi isn't available in Docker)
ENTRYPOINT ["python", "/app/service.py"]

# Default command with configurable options
CMD ["--standalone", "--config-dir", "/config"]