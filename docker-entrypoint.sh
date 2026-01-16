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

# Execute the main command
exec "$@"