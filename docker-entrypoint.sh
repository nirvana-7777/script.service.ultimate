#!/bin/bash
set -e

# Create DRM plugins directory structure if it doesn't exist
mkdir -p /app/lib/streaming_providers/base/drm/plugins

# Create symlink to volume-mounted DRM plugins
if [ ! -L /app/lib/streaming_providers/base/drm/plugins ]; then
    rm -rf /app/lib/streaming_providers/base/drm/plugins
    ln -sf /drm-plugins /app/lib/streaming_providers/base/drm/plugins
fi

# Ensure the mounted directory exists
mkdir -p /drm-plugins

# Copy default plugins if directory is empty (optional)
if [ -z "$(ls -A /drm-plugins)" ] && [ -d "/app/lib/streaming_providers/base/drm/default-plugins" ]; then
    echo "Copying default DRM plugins..."
    cp -r /app/lib/streaming_providers/base/drm/default-plugins/* /drm-plugins/
fi

# IMPORTANT: Ensure routes directory exists and has required files
# This is needed for the new split structure
if [ ! -d "/app/routes" ]; then
    echo "ERROR: routes directory not found!"
    echo "The service has been split into modules. Make sure routes/ directory exists in /app/"
    exit 1
fi

# Verify all required route files exist
REQUIRED_ROUTES=("__init__.py" "providers.py" "streams.py" "m3u.py" "drm.py" "cache.py" "config.py" "epg.py")
MISSING_FILES=0

for route in "${REQUIRED_ROUTES[@]}"; do
    if [ ! -f "/app/routes/$route" ]; then
        echo "ERROR: Missing required route file: /app/routes/$route"
        MISSING_FILES=$((MISSING_FILES + 1))
    fi
done

if [ $MISSING_FILES -gt 0 ]; then
    echo "ERROR: Missing $MISSING_FILES required route files. Service cannot start."
    exit 1
fi

# Set Python path to include routes directory
export PYTHONPATH="${PYTHONPATH}:/app"

echo "Routes directory check passed. Starting service..."

# Execute the main command
exec "$@"