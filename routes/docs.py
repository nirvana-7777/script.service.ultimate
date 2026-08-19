#!/usr/bin/env python3
"""
API Documentation route handlers
"""

import html as html_lib
import re
from bottle import response
from streaming_providers.base.utils import logger


# HTML template with placeholders for dynamic content
PAGE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Ultimate Backend API Documentation</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f7fa;
            color: #2d3748;
        }
        h1 {
            color: #2d3748;
            border-bottom: 3px solid #4299e1;
            padding-bottom: 10px;
        }
        .category {
            background: white;
            border-radius: 8px;
            margin: 20px 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .category-header {
            background: #4299e1;
            color: white;
            padding: 12px 20px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-weight: 600;
            user-select: none;
        }
        .category-header:hover {
            background: #3182ce;
        }
        .category-header .count {
            background: rgba(255,255,255,0.2);
            padding: 2px 12px;
            border-radius: 20px;
            font-size: 14px;
        }
        .endpoint-list {
            padding: 0;
            margin: 0;
        }
        .endpoint {
            display: flex;
            padding: 10px 20px;
            border-bottom: 1px solid #e2e8f0;
            align-items: flex-start;
            gap: 15px;
        }
        .endpoint:hover {
            background: #f7fafc;
        }
        .endpoint:last-child {
            border-bottom: none;
        }
        .method {
            font-weight: 700;
            padding: 2px 10px;
            border-radius: 4px;
            font-size: 12px;
            min-width: 60px;
            text-align: center;
            margin-top: 2px;
            flex-shrink: 0;
        }
        .method.GET { background: #48bb78; color: white; }
        .method.POST { background: #4299e1; color: white; }
        .method.PUT { background: #ed8936; color: white; }
        .method.DELETE { background: #fc8181; color: white; }
        .method.PATCH { background: #9f7aea; color: white; }
        .method.HEAD { background: #a0aec0; color: white; }
        .method.OPTIONS { background: #718096; color: white; }

        .path {
            font-family: "SF Mono", Monaco, Consolas, monospace;
            font-size: 14px;
            color: #2d3748;
            word-break: break-all;
            flex: 1;
        }
        .description {
            font-size: 13px;
            color: #718096;
            flex: 1.5;
        }
        .search-box {
            width: 100%;
            padding: 12px;
            font-size: 16px;
            border: 2px solid #e2e8f0;
            border-radius: 8px;
            margin: 20px 0;
            box-sizing: border-box;
        }
        .search-box:focus {
            outline: none;
            border-color: #4299e1;
        }
        .stats {
            display: flex;
            gap: 20px;
            margin: 10px 0 20px;
            flex-wrap: wrap;
        }
        .stat {
            background: white;
            padding: 8px 16px;
            border-radius: 8px;
            box-shadow: 0 1px 2px rgba(0,0,0,0.05);
        }
        .stat strong {
            color: #4299e1;
        }
        .actions {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            margin-bottom: 20px;
        }
        .expand-all {
            background: #48bb78;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
        }
        .expand-all:hover {
            background: #38a169;
        }
        .collapse-all {
            background: #fc8181;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
        }
        .collapse-all:hover {
            background: #f56565;
        }
        .endpoint-path {
            display: flex;
            align-items: center;
            gap: 10px;
            flex-wrap: wrap;
            flex: 1;
        }
        .parameter-hint {
            color: #a0aec0;
            font-size: 12px;
            font-style: italic;
        }
        .no-results {
            display: none;
            padding: 20px;
            text-align: center;
            color: #718096;
            font-size: 16px;
        }
        .no-results.visible {
            display: block;
        }
        .badge-deprecated {
            background: #fc8181;
            color: white;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 10px;
            font-weight: 600;
            text-transform: uppercase;
            margin-left: 8px;
        }
        @media (max-width: 768px) {
            .endpoint {
                flex-wrap: wrap;
                gap: 8px;
            }
            .method {
                min-width: 50px;
                font-size: 11px;
            }
            .description {
                flex: 1 1 100%;
                margin-left: 0;
            }
            body {
                padding: 10px;
            }
        }
    </style>
</head>
<body>
    <h1>🚀 Ultimate Backend API Documentation</h1>
    <div class="stats">
        <div class="stat">Total Endpoints: <strong>{{TOTAL}}</strong></div>
        <div class="stat">Categories: <strong>{{CATEGORIES_COUNT}}</strong></div>
    </div>

    <input type="text" class="search-box" id="search" placeholder="🔍 Search endpoints... (e.g., 'm3u', 'drm', 'channels')">

    <div class="actions">
        <button class="expand-all" onclick="expandAll()">▼ Expand All</button>
        <button class="collapse-all" onclick="collapseAll()">► Collapse All</button>
    </div>

    <div id="categories">
        {{ENDPOINTS}}
    </div>

    <div class="no-results" id="no-results">
        🔍 No endpoints match your search. Try a different term.
    </div>

    <script>
        // ------------------------------------------------------------------
        // Event delegation for category toggles (no inline onclick or IDs)
        // ------------------------------------------------------------------
        document.addEventListener('DOMContentLoaded', function() {
            // Toggle categories when header is clicked
            document.querySelectorAll('.category-header').forEach(function(header) {
                header.addEventListener('click', function() {
                    var list = this.nextElementSibling;
                    if (list && list.classList.contains('endpoint-list')) {
                        list.style.display = list.style.display === 'none' ? 'block' : 'none';
                    }
                });
            });

            // Collapse all by default
            collapseAll();

            // Search functionality
            var searchInput = document.getElementById('search');
            var noResults = document.getElementById('no-results');

            searchInput.addEventListener('input', function(e) {
                var query = e.target.value.toLowerCase().trim();
                var endpoints = document.querySelectorAll('.endpoint');
                var anyVisible = false;

                endpoints.forEach(function(endpoint) {
                    var path = (endpoint.dataset.path || '').toLowerCase();
                    var method = (endpoint.dataset.method || '').toLowerCase();
                    var desc = endpoint.querySelector('.description');
                    var descText = desc ? desc.textContent.toLowerCase() : '';

                    var match = !query || path.includes(query) || method.includes(query) || descText.includes(query);
                    endpoint.style.display = match ? 'flex' : 'none';
                    if (match) anyVisible = true;
                });

                // Show/hide empty categories
                document.querySelectorAll('.category').forEach(function(category) {
                    var visible = Array.from(category.querySelectorAll('.endpoint'))
                        .some(function(el) { return el.style.display !== 'none'; });
                    category.style.display = visible ? '' : 'none';
                });

                // Show/hide no results message
                noResults.classList.toggle('visible', !anyVisible && query.length > 0);
            });
        });

        // Expand all categories
        function expandAll() {
            document.querySelectorAll('.endpoint-list').forEach(function(el) {
                el.style.display = 'block';
            });
            document.getElementById('no-results').classList.remove('visible');
        }

        // Collapse all categories
        function collapseAll() {
            document.querySelectorAll('.endpoint-list').forEach(function(el) {
                el.style.display = 'none';
            });
        }
    </script>
</body>
</html>
"""


def setup_docs_routes(app, manager=None, service=None):
    """
    Setup API documentation routes.

    Args:
        app: Bottle application instance
        manager: Provider manager (unused but kept for consistent signature)
        service: Ultimate service instance (unused but kept for consistent signature)
    """
    # These are intentionally unused but kept for consistent API with other route modules
    # manager and service may be used in future versions for live API testing
    _ = manager, service  # Suppress lint warnings

    @app.route("/")
    def api_documentation():
        """
        Display all available API routes with descriptions
        """
        try:
            # Collect all routes from the Bottle app
            routes = []

            for route in app.routes:
                # Skip internal routes (like /_*, /static, /config)
                if route.rule.startswith('/_') or route.rule.startswith('/static'):
                    continue

                # Skip the docs route itself to avoid self-reference
                if route.rule == '/' and route.method == 'GET':
                    continue

                # Skip OPTIONS and HEAD (usually auto-generated)
                if route.method in ('OPTIONS', 'HEAD'):
                    continue

                # Get route info
                method = route.method
                rule = route.rule

                # Try to get the docstring from the route's callback
                docstring = None
                if hasattr(route, 'callback'):
                    callback = route.callback
                    if hasattr(callback, '__doc__'):
                        docstring = callback.__doc__
                    elif hasattr(callback, '__wrapped__') and hasattr(callback.__wrapped__, '__doc__'):
                        docstring = callback.__wrapped__.__doc__

                # Clean up docstring
                if docstring:
                    # Remove leading/trailing whitespace and get first line
                    docstring = docstring.strip().split('\n')[0].strip()
                else:
                    docstring = 'No description available'

                routes.append({
                    'method': method,
                    'path': rule,
                    'description': docstring
                })

            # Sort routes by path then method
            routes.sort(key=lambda r: (r['path'], r['method']))

            # Group routes by category
            categories = {
                'Providers': [],
                'Channels': [],
                'Streams': [],
                'M3U Playlists': [],
                'DRM & PSSH': [],
                'EPG': [],
                'VOD': [],
                'Events': [],
                'Recordings': [],
                'Timers': [],
                'Bookmarks': [],
                'Favorites': [],
                'Cache': [],
                'Configuration': [],
                'Other': []
            }

            # Categorize routes
            for route in routes:
                path = route['path']

                # Check for specific route patterns (order matters - most specific first)
                if '/m3u' in path:
                    categories['M3U Playlists'].append(route)
                elif '/drm' in path or '/pssh' in path:
                    categories['DRM & PSSH'].append(route)
                elif '/epg' in path:
                    categories['EPG'].append(route)
                elif '/cache' in path:
                    categories['Cache'].append(route)
                elif '/config' in path:
                    categories['Configuration'].append(route)
                elif '/bookmarks' in path:
                    categories['Bookmarks'].append(route)
                elif '/favorites' in path:
                    categories['Favorites'].append(route)
                elif '/providers' in path:
                    # Provider-relative routes
                    if '/channels' in path:
                        if '/stream' in path:
                            categories['Streams'].append(route)
                        elif '/epg' in path:
                            categories['EPG'].append(route)
                        else:
                            categories['Channels'].append(route)
                    elif '/vod' in path:
                        categories['VOD'].append(route)
                    elif '/events' in path:
                        categories['Events'].append(route)
                    elif '/recordings' in path:
                        categories['Recordings'].append(route)
                    elif '/timers' in path:
                        categories['Timers'].append(route)
                    elif '/m3u' in path:
                        categories['M3U Playlists'].append(route)
                    else:
                        categories['Providers'].append(route)
                else:
                    categories['Other'].append(route)

            # Remove empty categories
            categories = {k: v for k, v in categories.items() if v}

            # Build endpoints HTML with proper escaping
            endpoints_html = ""
            total_routes = 0

            for category, routes_list in categories.items():
                total_routes += len(routes_list)
                category_escaped = html_lib.escape(category)

                # No inline onclick or IDs - uses event delegation in JS
                endpoints_html += f'<div class="category" data-category="{category_escaped}">'
                endpoints_html += f'<div class="category-header">'
                endpoints_html += f'<span>{category_escaped}</span>'
                endpoints_html += f'<span class="count">{len(routes_list)} endpoints</span>'
                endpoints_html += '</div>'
                endpoints_html += '<div class="endpoint-list">'

                for route in routes_list:
                    method = html_lib.escape(route['method'])
                    path = html_lib.escape(route['path'])
                    desc = html_lib.escape(route['description'])

                    # Replace path parameters with styled spans
                    # Match escaped angle brackets from html.escape
                    path_display = re.sub(
                        r'&lt;([^:&gt;]+):([^&gt;]+)&gt;',
                        r'<span class="parameter-hint">:\2</span>',
                        path
                    )
                    path_display = re.sub(
                        r'&lt;([^&gt;]+)&gt;',
                        r'<span class="parameter-hint">\1</span>',
                        path_display
                    )

                    endpoints_html += (
                        f'<div class="endpoint" data-method="{method}" data-path="{path}">'
                    )
                    endpoints_html += f'<span class="method {method}">{method}</span>'
                    endpoints_html += f'<div class="endpoint-path"><span class="path">{path_display}</span></div>'
                    endpoints_html += f'<span class="description">{desc}</span>'
                    endpoints_html += '</div>'

                endpoints_html += '</div></div>'

            # Build final page using replace to avoid format() brace issues
            page = PAGE_TEMPLATE
            page = page.replace("{{ENDPOINTS}}", endpoints_html)
            page = page.replace("{{TOTAL}}", str(total_routes))
            page = page.replace("{{CATEGORIES_COUNT}}", str(len(categories)))

            response.content_type = "text/html; charset=utf-8"
            return page

        except Exception as e:
            logger.error(f"Error generating API documentation: {e}")
            response.status = 500
            response.content_type = "application/json"
            return {"error": "Failed to generate API documentation", "message": str(e)}

    @app.route("/api/docs")
    def api_docs_json():
        """
        Get API documentation as JSON (machine-readable format)
        """
        try:
            routes = []

            for route in app.routes:
                # Skip internal routes
                if route.rule.startswith('/_') or route.rule.startswith('/static'):
                    continue

                if route.rule == '/' and route.method == 'GET':
                    continue

                if route.method in ('OPTIONS', 'HEAD'):
                    continue

                docstring = None
                if hasattr(route, 'callback'):
                    callback = route.callback
                    if hasattr(callback, '__doc__'):
                        docstring = callback.__doc__
                    elif hasattr(callback, '__wrapped__') and hasattr(callback.__wrapped__, '__doc__'):
                        docstring = callback.__wrapped__.__doc__

                if docstring:
                    docstring = docstring.strip().split('\n')[0].strip()

                routes.append({
                    'method': route.method,
                    'path': route.rule,
                    'description': docstring or 'No description available'
                })

            routes.sort(key=lambda r: (r['path'], r['method']))

            response.content_type = "application/json; charset=utf-8"
            return {
                'total': len(routes),
                'routes': routes
            }

        except Exception as e:
            logger.error(f"Error generating JSON API docs: {e}")
            response.status = 500
            response.content_type = "application/json"
            return {"error": "Failed to generate API documentation", "message": str(e)}