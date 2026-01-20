#!/usr/bin/env python3
"""
Stream and manifest route handlers
"""

from datetime import datetime

from bottle import HTTPResponse, redirect, request, response
from streaming_providers.base.utils import logger


def setup_stream_routes(app, manager, service):
    """Setup stream and manifest-related routes"""

    @app.route("/api/providers/<provider>/channels/<channel_id>/manifest")
    def get_channel_manifest(provider, channel_id):
        """
        Get channel manifest. Always returns JSON with manifest_url pointing to stream endpoint.
        """
        try:
            # Build the stream URL (which will handle both proxy and non-proxy)
            base_url = f"{request.urlparts.scheme}://{request.urlparts.netloc}"
            stream_url = (
                f"{base_url}/api/providers/{provider}/channels/{channel_id}/stream"
            )

            # Add country parameter if provided
            country = request.query.get("country")
            if country:
                stream_url += f"?country={country}"

            return {
                "provider": provider,
                "channel_id": channel_id,
                "manifest_url": stream_url,  # Always point to /stream endpoint
            }

        except ValueError as val_err:
            logger.error(
                f"API Error in /api/providers/{provider}/channels/{channel_id}/manifest: {str(val_err)}"
            )
            response.status = 404
            return {"error": str(val_err)}
        except Exception as api_err:
            logger.error(
                f"API Error in /api/providers/{provider}/channels/{channel_id}/manifest: {str(api_err)}"
            )
            response.status = 500
            return {"error": f"Internal server error: {str(api_err)}"}

    @app.route("/api/providers/<provider>/channels/<channel_id>/stream")
    def get_channel_stream(provider, channel_id):
        """
        Returns HTTP 302 redirect to the actual manifest or rewritten manifest endpoint.
        Supports both live and catchup streaming.
        """
        try:
            # Get optional catchup parameters
            start_time = request.query.get("start_time")
            end_time = request.query.get("end_time")
            epg_id = request.query.get("epg_id")
            country = request.query.get("country")

            # Determine if this is a catchup request
            is_catchup = bool(start_time and end_time)

            if is_catchup:
                logger.info(
                    f"Catchup stream request for {provider}/{channel_id}: "
                    f"start={start_time}, end={end_time}, epg_id={epg_id}"
                )

                # Convert Unix timestamps to integers
                try:
                    start_time_int = int(start_time)
                    end_time_int = int(end_time)
                except (ValueError, TypeError):
                    response.status = 400
                    return {"error": "Invalid start_time or end_time format"}

                # Validate catchup is supported
                provider_instance = manager.get_provider(provider)
                catchup_hours = getattr(
                    provider_instance, "catchup_window", 0
                )  # Now in hours

                if catchup_hours == 0:
                    response.status = 400
                    return {"error": f'Catchup not supported for provider "{provider}"'}

                # Validate time is within catchup window (in HOURS)
                import time

                now = int(time.time())
                max_age_seconds = catchup_hours * 3600  # Hours to seconds

                if (now - start_time_int) > max_age_seconds:
                    response.status = 400
                    return {
                        "error": f"Content outside catchup window (max {catchup_hours} hours)"
                    }

                # Check if provider needs proxy for catchup
                if manager.needs_proxy(provider):
                    # Proxy mode: return rewritten MPD content directly
                    return service._get_proxied_catchup_manifest(
                        provider,
                        channel_id,
                        start_time_int,
                        end_time_int,
                        epg_id,
                        country,
                    )
                else:
                    # Direct mode: get catchup manifest URL and redirect
                    manifest_url = manager.get_catchup_manifest(
                        provider_name=provider,
                        channel_id=channel_id,
                        start_time=start_time_int,
                        end_time=end_time_int,
                        epg_id=epg_id,
                        country=country,
                    )

                    if not manifest_url:
                        response.status = 404
                        return {
                            "error": f'Catchup manifest not available for channel "{channel_id}"'
                        }

                    logger.debug(f"Redirecting to catchup manifest: {manifest_url}")
                    redirect(manifest_url)
            else:
                # Live stream - existing logic
                if manager.needs_proxy(provider):
                    return service._get_proxied_manifest(provider, channel_id)
                else:
                    manifest_url = manager.get_channel_manifest(
                        provider_name=provider,
                        channel_id=channel_id,
                        country=country,
                    )

                    if not manifest_url:
                        response.status = 404
                        return {
                            "error": f'Manifest not available for channel "{channel_id}"'
                        }

                    logger.debug(f"Redirecting to manifest: {manifest_url}")
                    redirect(manifest_url)

        except HTTPResponse:
            raise
        except ValueError as val_err:
            logger.error(f"API Error in stream: {str(val_err)}")
            response.status = 404
            return {"error": str(val_err)}
        except Exception as api_err:
            logger.error(f"API Error in stream: {str(api_err)}")
            response.status = 500
            return {"error": f"Internal server error: {str(api_err)}"}

    @app.route("/api/providers/<provider>/channels/<channel_id>/epg")
    def get_channel_epg(provider, channel_id):
        try:
            # Parse optional parameters
            kwargs = {"country": request.query.get("country")}

            from datetime import timezone

            # Handle start_time - can be Unix timestamp (from Kodi) or datetime
            if request.query.get("start_time"):
                start_time_str = request.query.get("start_time")
                try:
                    # Try to parse as Unix timestamp (integer from Kodi PVR)
                    start_time_int = int(start_time_str)
                    kwargs["start_time"] = datetime.fromtimestamp(
                        start_time_int, tz=timezone.utc
                    )
                except (ValueError, TypeError):
                    # Try to parse as ISO format string (for manual API calls)
                    try:
                        kwargs["start_time"] = datetime.fromisoformat(
                            start_time_str.replace("Z", "+00:00")
                        )
                    except ValueError:
                        logger.warning(f"Invalid start_time format: {start_time_str}")
                        # Continue without start_time filter
                        pass

            # Handle end_time - can be Unix timestamp or datetime
            if request.query.get("end_time"):
                end_time_str = request.query.get("end_time")
                try:
                    # Try to parse as Unix timestamp (integer from Kodi PVR)
                    end_time_int = int(end_time_str)
                    kwargs["end_time"] = datetime.fromtimestamp(
                        end_time_int, tz=timezone.utc
                    )
                except (ValueError, TypeError):
                    # Try to parse as ISO format string (for manual API calls)
                    try:
                        kwargs["end_time"] = datetime.fromisoformat(
                            end_time_str.replace("Z", "+00:00")
                        )
                    except ValueError:
                        logger.warning(f"Invalid end_time format: {end_time_str}")
                        # Continue without end_time filter
                        pass

            # Get EPG data from manager
            epg_data = manager.get_channel_epg(
                provider_name=provider, channel_id=channel_id, **kwargs
            )

            # Return as JSON
            response.content_type = "application/json; charset=utf-8"
            return {"provider": provider, "channel_id": channel_id, "epg": epg_data}

        except ValueError as val_err:
            # This handles the case where manager raises ValueError for unknown provider
            logger.error(
                f"API Error in /api/providers/{provider}/channels/{channel_id}/epg: {str(val_err)}"
            )
            response.status = 404
            response.content_type = "application/json; charset=utf-8"
            return {"error": str(val_err)}
        except Exception as api_err:
            logger.error(
                f"API Error in /api/providers/{provider}/channels/{channel_id}/epg: {str(api_err)}"
            )
            response.status = 500
            response.content_type = "application/json; charset=utf-8"
            return {"error": f"Internal server error: {str(api_err)}"}

    @app.route("/api/providers/<provider>/epg")
    def get_provider_epg_xmltv(provider):
        try:
            # Set appropriate headers for XMLTV
            response.content_type = "application/xml; charset=utf-8"
            response.headers["Content-Disposition"] = (
                f'attachment; filename="{provider}_epg.xml"'
            )

            # Get the XMLTV data from the provider
            xmltv_data = manager.get_provider_epg_xmltv(
                provider_name=provider, country=request.query.get("country")
            )

            if not xmltv_data:
                response.status = 404
                return {"error": f'EPG data not available for provider "{provider}"'}

            return xmltv_data

        except ValueError as val_err:
            # Handle unknown provider
            logger.error(f"API Error in /api/providers/{provider}/epg: {str(val_err)}")
            response.status = 404
            return {"error": str(val_err)}
        except Exception as api_err:
            logger.error(f"API Error in /api/providers/{provider}/epg: {str(api_err)}")
            response.status = 500
            return {"error": f"Internal server error: {str(api_err)}"}

    @app.route("/api/providers/<provider>/channels/<channel_id>/drm")
    def get_channel_drm(provider, channel_id):
        try:
            # Get optional catchup parameters
            start_time = request.query.get("start_time")
            end_time = request.query.get("end_time")
            epg_id = request.query.get("epg_id")
            country = request.query.get("country")

            # Determine if this is a catchup request
            is_catchup = bool(start_time and end_time)

            if is_catchup:
                logger.debug(
                    f"Catchup DRM request for {provider}/{channel_id}: "
                    f"epg_id={epg_id}"
                )

                # Convert timestamps
                try:
                    start_time_int = int(start_time)
                    end_time_int = int(end_time)
                except (ValueError, TypeError):
                    response.status = 400
                    return {"error": "Invalid start_time or end_time format"}

                # Get catchup DRM configs
                drm_configs = manager.get_catchup_drm_configs(
                    provider_name=provider,
                    channel_id=channel_id,
                    start_time=start_time_int,
                    end_time=end_time_int,
                    epg_id=epg_id,
                    country=country,
                )
            else:
                # Live DRM - existing logic
                drm_configs = manager.get_channel_drm_configs(
                    provider_name=provider, channel_id=channel_id, country=country
                )

            # Merge all DRM configs into a single dictionary
            merged_drm_configs = {}
            for config in drm_configs:
                if hasattr(config, "to_dict"):
                    config_dict = config.to_dict()
                else:
                    config_dict = config
                merged_drm_configs.update(config_dict)

            return {
                "provider": provider,
                "channel_id": channel_id,
                "is_catchup": is_catchup,
                "drm_configs": merged_drm_configs,
            }

        except ValueError as val_err:
            logger.error(f"API Error in DRM endpoint: {str(val_err)}")
            response.status = 404
            return {"error": str(val_err)}
        except Exception as api_err:
            logger.error(f"API Error in DRM endpoint: {str(api_err)}")
            response.status = 500
            return {"error": f"Internal server error: {str(api_err)}"}

    @app.route("/api/providers/<provider>/channels/<channel_id>/stream/decrypted")
    def get_channel_stream_decrypted(provider, channel_id):
        """
        Returns rewritten manifest for decrypted playback via media proxy.
        This endpoint is used by the decrypted M3U playlists.
        """
        try:
            # Check if media proxy is configured
            if not service.media_proxy_url:
                response.status = 503
                return {"error": "Media proxy not configured (MEDIA_PROXY_URL not set)"}

            country = request.query.get("country")

            # Get DRM configs to extract ClearKey data
            drm_configs = manager.get_channel_drm_configs(
                provider_name=provider, channel_id=channel_id, country=country
            )

            # Extract ClearKey data
            clearkey_data = None
            if isinstance(drm_configs, dict) and "org.w3.clearkey" in drm_configs:
                clearkey_data = drm_configs["org.w3.clearkey"]

            if not clearkey_data:
                response.status = 400
                return {"error": f'Channel "{channel_id}" does not have ClearKey DRM'}

            # Extract KID:Key pairs
            license_info = clearkey_data.get("license", {})
            keyids = license_info.get("keyids", {})

            if not keyids:
                response.status = 400
                return {"error": f'No ClearKey keyids found for channel "{channel_id}"'}

            # Get manifest (check if needs proxy)
            if manager.needs_proxy(provider):
                # Get rewritten manifest with media proxy URLs + decrypt params
                return service._get_decrypted_manifest(provider, channel_id, keyids)
            else:
                # No proxy needed - return error (decryption requires media proxy)
                response.status = 400
                return {
                    "error": "Decrypted playback requires provider proxy configuration"
                }

        except ValueError as val_err:
            logger.error(f"API Error in decrypted stream: {str(val_err)}")
            response.status = 404
            return {"error": str(val_err)}
        except Exception as api_err:
            logger.error(f"API Error in decrypted stream: {str(api_err)}")
            response.status = 500
            return {"error": f"Internal server error: {str(api_err)}"}
