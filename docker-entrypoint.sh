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

# IMPORTANT: Verify the new split routes structure
# The routes are now split across:
#   - routes/*.py (top-level route files)
#   - routes/streams/*.py (split stream modules)

if [ ! -d "/app/routes" ]; then
    echo "ERROR: routes directory not found!"
    echo "The service has been split into modules. Make sure routes/ directory exists in /app/"
    exit 1
fi

# Verify all required top-level route files exist
REQUIRED_TOP_ROUTES=("__init__.py" "providers.py" "m3u.py" "drm.py" "cache.py" "config.py" "epg.py" "events.py" "vod.py" "recordings.py" "timers.py" "bookmarks.py" "favorites.py")
MISSING_FILES=0

for route in "${REQUIRED_TOP_ROUTES[@]}"; do
    if [ ! -f "/app/routes/$route" ]; then
        echo "ERROR: Missing required route file: /app/routes/$route"
        MISSING_FILES=$((MISSING_FILES + 1))
    fi
done

# Verify the streams subdirectory exists
if [ ! -d "/app/routes/streams" ]; then
    echo "ERROR: Missing routes/streams directory! This is required for the split stream modules."
    MISSING_FILES=$((MISSING_FILES + 1))
else
    # Verify all required stream module files exist
    REQUIRED_STREAM_MODULES=("__init__.py" "channels.py" "events.py" "vod.py" "recordings.py" "epg.py")
    for module in "${REQUIRED_STREAM_MODULES[@]}"; do
        if [ ! -f "/app/routes/streams/$module" ]; then
            echo "ERROR: Missing required stream module: /app/routes/streams/$module"
            MISSING_FILES=$((MISSING_FILES + 1))
        fi
    done
fi

if [ $MISSING_FILES -gt 0 ]; then
    echo "ERROR: Missing $MISSING_FILES required route files/modules. Service cannot start."
    exit 1
fi

# Set Python path to include app directory (for absolute imports)
export PYTHONPATH="${PYTHONPATH}:/app"

# Verify Python can import the routes module
echo "Testing Python imports..."
python3 -c "
import sys
sys.path.insert(0, '/app')
try:
    from routes.streams import setup_stream_routes
    print('✓ routes.streams module loaded successfully')
except ImportError as e:
    print(f'✗ Failed to import routes.streams: {e}')
    sys.exit(1)
try:
    from routes import providers, m3u, drm, cache, config, epg, events, vod, recordings, timers, bookmarks, favorites
    print('✓ All top-level route modules loaded successfully')
except ImportError as e:
    print(f'✗ Failed to import top-level route modules: {e}')
    sys.exit(1)
print('All imports successful!')
" || exit 1

echo "Routes directory check passed. Starting service..."

# Execute the main command
exec "$@"