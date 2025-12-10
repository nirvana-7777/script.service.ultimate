# Use Python 3.11 slim as base
FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TZ=UTC \
    ULTIMATE_PORT=7777 \
    ULTIMATE_COUNTRY=DE \
    PYTHONPATH=/app/lib:$PYTHONPATH

# Create non-root user
RUN useradd -m -u 1000 -s /bin/bash kodi

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libxml2-dev \
    libxslt-dev \
    libffi-dev \
    libssl-dev \
    libxmlsec1-dev \
    pkg-config \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy entire project
COPY . /app/

# Create config directory and ensure proper permissions
RUN mkdir -p /config && \
    chown -R kodi:kodi /app /config

USER kodi

# Install Python dependencies
RUN pip install --no-cache-dir --user \
    bottle \
    requests \
    lxml \
    defusedxml \
    m3u8 \
    iso8601 \
    pycountry \
    python-dateutil \
    urllib3 \
    chardet \
    pycryptodome \
    cryptography

# Create requirements.txt for documentation
RUN echo "bottle>=0.12.25" > /app/requirements.txt && \
    echo "requests>=2.31.0" >> /app/requirements.txt && \
    echo "lxml>=4.9.3" >> /app/requirements.txt && \
    echo "defusedxml>=0.7.1" >> /app/requirements.txt && \
    echo "m3u8>=4.0.0" >> /app/requirements.txt && \
    echo "iso8601>=1.1.0" >> /app/requirements.txt && \
    echo "pycountry>=23.12.11" >> /app/requirements.txt && \
    echo "python-dateutil>=2.8.2" >> /app/requirements.txt && \
    echo "urllib3>=2.0.7" >> /app/requirements.txt && \
    echo "chardet>=5.2.0" >> /app/requirements.txt && \
    echo "pycryptodome>=3.19.0" >> /app/requirements.txt && \
    echo "cryptography>=41.0.0" >> /app/requirements.txt

# Expose the service port
EXPOSE ${ULTIMATE_PORT}

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${ULTIMATE_PORT}/api/providers || exit 1

# Run in standalone mode (since Kodi isn't available in Docker)
ENTRYPOINT ["python", "/app/service.py"]

# Default command
CMD ["--standalone", "--config-dir", "/config"]