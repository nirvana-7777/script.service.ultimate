#!/usr/bin/env python3
"""
Provider-related route handlers
"""

from bottle import request, response
from streaming_providers.base.utils import logger


def setup_provider_routes(app, manager, service):
    """Setup provider-related routes"""

    @app.route("/api/providers")
    def list_providers():
        try:
            # Get metadata for ALL providers (enabled + disabled)
            all_metadata = manager.get_all_providers_metadata()

            # For backward compatibility, also get details for enabled providers
            enabled_providers = []
            for metadata in all_metadata:
                if metadata["enabled"] and metadata["instance_ready"]:
                    provider_instance = manager.get_provider(metadata["name"])
                    if provider_instance:
                        # Get detailed auth info from instance
                        supported_auth_types = getattr(
                            provider_instance, "supported_auth_types", []
                        )
                        preferred_auth_type = getattr(
                            provider_instance, "preferred_auth_type", "unknown"
                        )
                        requires_stored_credentials = getattr(
                            provider_instance, "requires_stored_credentials", False
                        )

                        # Check specific auth type needs
                        needs_user_creds = "user_credentials" in supported_auth_types
                        needs_client_creds = (
                            "client_credentials" in supported_auth_types
                        )
                        is_network_based = "network_based" in supported_auth_types
                        is_anonymous = "anonymous" in supported_auth_types
                        uses_device_reg = "device_registration" in supported_auth_types
                        uses_embedded = "embedded_client" in supported_auth_types

                        provider_details = {
                            "name": metadata["name"],
                            "label": metadata["label"],
                            "logo": metadata["logo"],
                            "country": metadata["country"],
                            # Core authentication properties
                            "auth": {
                                "supported_auth_types": supported_auth_types,
                                "preferred_auth_type": preferred_auth_type,
                                "requires_stored_credentials": requires_stored_credentials,
                                # Specific auth type flags for easy UI decisions
                                "needs_user_credentials": needs_user_creds,
                                "needs_client_credentials": needs_client_creds,
                                "is_network_based": is_network_based,
                                "is_anonymous": is_anonymous,
                                "uses_device_registration": uses_device_reg,
                                "uses_embedded_client": uses_embedded,
                                # Derived summary for UI
                                "needs_user_input": needs_user_creds or uses_device_reg,
                                "needs_configuration": needs_user_creds
                                or needs_client_creds,
                                "is_automatic": is_network_based
                                or is_anonymous
                                or uses_embedded,
                            },
                            # Token properties
                            "primary_token_scope": getattr(
                                provider_instance, "primary_token_scope", None
                            ),
                            "token_scopes": getattr(
                                provider_instance, "token_scopes", []
                            ),
                            # Metadata fields
                            "enabled": metadata["enabled"],
                            "instance_ready": metadata["instance_ready"],
                            "requires_credentials": metadata["requires_credentials"],
                        }
                        enabled_providers.append(provider_details)

            return {
                "providers": enabled_providers,
                "all_providers": all_metadata,  # NEW: Include all providers metadata
                "default_country": service.default_country,
            }
        except Exception as api_err:
            logger.error(f"API Error in /api/providers: {str(api_err)}")
            response.status = 500
            return {"error": str(api_err)}

    @app.route("/api/providers/<provider>/channels")
    def get_channels(provider):
        try:
            channels = manager.get_channels(
                provider_name=provider,
                fetch_manifests=request.query.get("fetch_manifests", "false").lower()
                == "true",
                country=request.query.get("country"),
            )

            # Get provider instance to check catchup support
            provider_instance = manager.get_provider(provider)
            provider_catchup_hours = getattr(
                provider_instance, "catchup_window", 0
            )  # CHANGE

            # Build channel list with catchup info
            channels_data = []
            for c in channels:
                channel_dict = c.to_dict()

                # Add catchup hours - use channel-specific if available, else provider default
                if hasattr(c, "catchup_hours"):  # CHANGE
                    channel_dict["CatchupHours"] = c.catchup_hours  # CHANGE
                else:
                    channel_dict["CatchupHours"] = provider_catchup_hours  # CHANGE

                channels_data.append(channel_dict)

            return {
                "provider": provider,
                "country": provider_instance.country if provider_instance else "DE",
                "catchup_window_hours": provider_catchup_hours,  # CHANGE
                "channels": channels_data,
            }
        except Exception as api_err:
            logger.error(f"API Error in /api/providers/{provider}: {str(api_err)}")
            response.status = 500
            return {"error": str(api_err)}

    @app.route("/api/providers/<provider>/auth/status")
    def get_provider_auth_status(provider):
        """Get authentication status from provider itself"""
        try:
            # Get provider instance
            provider_instance = manager.get_provider(provider)
            if not provider_instance:
                response.status = 404
                return {"error": f"Provider {provider} not found"}

            # Get SettingsManager
            settings_manager = service._get_settings_manager()
            if not settings_manager:
                response.status = 500
                return {"error": "Settings manager not available"}

            # Import and use new auth system
            from streaming_providers.providers.auth_context import AuthContext

            try:
                auth_context = AuthContext(settings_manager)
                auth_status = provider_instance.get_auth_status(auth_context)
                return auth_status.to_dict()
            except AttributeError as attr_err:
                logger.error(
                    f"Provider {provider} missing required auth property: {attr_err}"
                )
                response.status = 501  # Not Implemented
                return {
                    "error": f"Provider {provider} does not fully implement auth status",
                    "details": str(attr_err),
                }
            except Exception as e:
                logger.error(f"Error getting auth status: {e}", exc_info=True)
                response.status = 500
                return {"error": str(e)}

        except ImportError as import_error:
            # This happens during development if modules not created yet
            logger.warning(f"Auth modules not available: {import_error}")
            return {
                "provider": provider,
                "auth_state": "not_implemented",
                "is_ready": False,
                "message": "New auth system in development",
            }
        except Exception as e:
            logger.error(
                f"Error getting auth status for {provider}: {e}", exc_info=True
            )
            response.status = 500
            return {"error": f"Internal server error: {str(e)}"}

    @app.route("/api/providers/<provider>/credentials", method="GET")
    def get_provider_credentials(provider):
        """
        GET: Retrieve current credentials (masked for security)

        Example: GET /api/providers/joyn/credentials
        Returns: {
            "has_credentials": true,
            "credential_type": "user_password",
            "username_masked": "us***@example.com",
            "username": "user@example.com"  # Note: only included for pre-fill with user consent
        }
        """
        try:
            settings_manager = service._get_settings_manager()

            # Parse provider and country
            provider_name, country = settings_manager.parse_provider_country(provider)

            # Get credentials
            credentials = settings_manager.get_provider_credentials(
                provider_name, country
            )

            response_data = {
                "provider": provider,
                "has_credentials": credentials is not None,
                "credential_type": None,
                "username_masked": None,
                "username": None,  # We'll include this only if user explicitly allows
            }

            if credentials:
                response_data["credential_type"] = credentials.credential_type
                response_data["is_valid"] = credentials.validate()

                # Get username if it exists (for user_password credentials)
                if hasattr(credentials, "username") and credentials.username:
                    username = credentials.username

                    # Create masked version for display
                    if "@" in username:  # Email address
                        parts = username.split("@")
                        if len(parts[0]) > 2:
                            masked = parts[0][:2] + "***@" + parts[1]
                        else:
                            masked = "***@" + parts[1]
                    else:  # Username
                        if len(username) > 4:
                            masked = username[:2] + "***" + username[-2:]
                        else:
                            masked = "***"

                    response_data["username_masked"] = masked

                    # For pre-filling forms (security consideration - you can omit this)
                    # Only include if you trust your frontend and have HTTPS
                    response_data["username"] = username

                # Log for debugging (remove in production)
                logger.debug(
                    f"GET credentials for {provider}: type={credentials.credential_type}, has_username={hasattr(credentials, 'username')}"
                )

            return response_data

        except Exception as e:
            logger.error(f"GET credentials error for {provider}: {e}", exc_info=True)
            response.status = 500
            return {"error": f"Internal server error: {str(e)}"}

    @app.route("/api/providers/<provider>/credentials", method="POST")
    def save_provider_credentials(provider):
        """
        Save credentials for a provider via API

        Accepts JSON body with credentials:
        - User/password: {"username": "...", "password": "..."}
        - For updates: {"password": "..."} (keep existing username)
        """
        try:
            # Parse JSON body
            try:
                credentials_data = request.json
                logger.debug(
                    f"Received credentials data for {provider}: {credentials_data}"
                )
            except Exception as json_err:
                logger.error(f"Invalid JSON in request body: {json_err}")
                response.status = 400
                return {"error": "Invalid JSON in request body"}

            if not credentials_data:
                logger.error("No credentials data provided")
                response.status = 400
                return {"error": "Request body must contain credentials data"}

            # Validate it's a dictionary
            if not isinstance(credentials_data, dict):
                logger.error(
                    f"Credentials data is not a dict: {type(credentials_data)}"
                )
                response.status = 400
                return {"error": "Credentials data must be a JSON object"}

            # Get settings manager
            settings_manager = service._get_settings_manager()

            # Parse provider and country
            provider_name, country = settings_manager.parse_provider_country(provider)

            # Check if we have existing credentials (for partial updates)
            existing_credentials = settings_manager.get_provider_credentials(
                provider_name, country
            )

            if existing_credentials and "username" not in credentials_data:
                # Partial update - keep existing username, only update password
                if hasattr(existing_credentials, "username"):
                    credentials_data["username"] = existing_credentials.username
                else:
                    response.status = 400
                    return {
                        "error": "Cannot update - existing credentials do not have username"
                    }

            # Save credentials
            success, message = settings_manager.save_provider_credentials_from_api(
                provider, credentials_data
            )

            logger.info(
                f"Save result for {provider}: success={success}, message={message}"
            )

            if success:
                # Reinitialize provider to pick up new credentials
                reinit_success = manager.reinitialize_provider(provider)
                if not reinit_success:
                    logger.warning(
                        f"Failed to reinitialize provider '{provider}' after credential change"
                    )

                response.status = 200
                response.content_type = "application/json; charset=utf-8"
                return {
                    "success": True,
                    "provider": provider,
                    "message": message,
                    "action": "updated" if existing_credentials else "created",
                    "reinitialized": reinit_success,
                }
            else:
                # Determine appropriate status code
                if "not registered" in message.lower():
                    response.status = 404
                elif (
                    "invalid" in message.lower()
                    or "validation failed" in message.lower()
                ):
                    response.status = 400
                else:
                    response.status = 500

                return {"error": message}

        except Exception as api_err:
            logger.error(
                f"API Error in POST /api/providers/{provider}/credentials: {str(api_err)}",
                exc_info=True,
            )
            response.status = 500
            return {"error": f"Internal server error: {str(api_err)}"}

    @app.route("/api/providers/<provider>/credentials", method="DELETE")
    def delete_provider_credentials(provider):
        """
        Delete credentials for a provider via API

        Example: DELETE /api/providers/joyn_de/credentials
        """
        try:
            settings_manager = service._get_settings_manager()
            success, message = settings_manager.delete_provider_credentials_from_api(
                provider
            )

            if success:
                # Reinitialize provider to clear any cached authentication
                reinit_success = manager.reinitialize_provider(provider)
                if not reinit_success:
                    logger.warning(
                        f"Failed to reinitialize provider '{provider}' after credential deletion"
                    )

                response.status = 200
                response.content_type = "application/json; charset=utf-8"
                return {
                    "success": True,
                    "provider": provider,
                    "message": message,
                    "reinitialized": reinit_success,
                }
            else:
                # Determine appropriate status code
                if "not registered" in message.lower():
                    response.status = 404
                else:
                    response.status = 500

                return {"error": message}

        except Exception as api_err:
            logger.error(
                f"API Error in DELETE /api/providers/{provider}/credentials: {str(api_err)}"
            )
            response.status = 500
            return {"error": f"Internal server error: {str(api_err)}"}

    @app.route("/api/providers/<provider>/proxy", method="GET")
    def get_provider_proxy(provider):
        """
        Get current proxy configuration for a provider

        Example: GET /api/providers/joyn/proxy
        """
        try:
            settings_manager = service._get_settings_manager()

            # Parse provider and country
            provider_name, country = settings_manager.parse_provider_country(provider)

            # Get proxy config
            proxy_config = settings_manager.get_provider_proxy(provider_name, country)

            if proxy_config:
                return {
                    "success": True,
                    "provider": provider,
                    "proxy_config": (
                        proxy_config.to_dict()
                        if hasattr(proxy_config, "to_dict")
                        else proxy_config
                    ),
                }
            else:
                return {
                    "success": True,
                    "provider": provider,
                    "proxy_config": None,
                    "message": "No proxy configuration found",
                }

        except Exception as api_err:
            logger.error(
                f"API Error in GET /api/providers/{provider}/proxy: {str(api_err)}"
            )
            response.status = 500
            return {"error": f"Internal server error: {str(api_err)}"}

    @app.route("/api/providers/<provider>/proxy", method="POST")
    def save_provider_proxy(provider):
        """
        Save proxy configuration for a provider via API

        Accepts JSON body with proxy configuration:
        Required: {"host": "proxy.example.com", "port": 8080}
        Optional: {
            "proxy_type": "http",  # http, https, socks4, socks5
            "username": "proxyuser",
            "password": "proxypass",
            "timeout": 30,
            "verify_ssl": true,
            "scope": {
                "api_calls": true,
                "authentication": true,
                "manifests": true,
                "license": true,
                "all": true
            }
        }

        Example: POST /api/providers/joyn_de/proxy
        Body: {"host": "proxy.example.com", "port": 8080}
        """
        try:
            # Parse JSON body
            try:
                proxy_data = request.json
            except Exception as json_err:
                logger.error(f"Invalid JSON in request body: {json_err}")
                response.status = 400
                return {"error": "Invalid JSON in request body"}

            if not proxy_data:
                response.status = 400
                return {"error": "Request body must contain proxy configuration"}

            # Validate it's a dictionary
            if not isinstance(proxy_data, dict):
                response.status = 400
                return {"error": "Proxy data must be a JSON object"}

            settings_manager = service._get_settings_manager()
            success, message = settings_manager.save_provider_proxy_from_api(
                provider, proxy_data
            )

            if success:
                # Reinitialize provider to pick up new proxy configuration
                reinit_success = manager.reinitialize_provider(provider)
                if not reinit_success:
                    logger.warning(
                        f"Failed to reinitialize provider '{provider}' after proxy change"
                    )

                response.status = 200
                response.content_type = "application/json; charset=utf-8"
                return {
                    "success": True,
                    "provider": provider,
                    "message": message,
                    "reinitialized": reinit_success,
                }
            else:
                # Determine appropriate status code
                if "not registered" in message.lower():
                    response.status = 404
                elif (
                    "invalid" in message.lower()
                    or "validation failed" in message.lower()
                ):
                    response.status = 400
                else:
                    response.status = 500

                return {"error": message}

        except Exception as api_err:
            logger.error(
                f"API Error in POST /api/providers/{provider}/proxy: {str(api_err)}"
            )
            response.status = 500
            return {"error": f"Internal server error: {str(api_err)}"}

    @app.route("/api/providers/<provider>/proxy", method="DELETE")
    def delete_provider_proxy(provider):
        """
        Delete proxy configuration for a provider via API

        Example: DELETE /api/providers/joyn_de/proxy
        """
        try:
            settings_manager = service._get_settings_manager()
            success, message = settings_manager.delete_provider_proxy_from_api(provider)

            if success:
                # Reinitialize provider to remove proxy configuration
                reinit_success = manager.reinitialize_provider(provider)
                if not reinit_success:
                    logger.warning(
                        f"Failed to reinitialize provider '{provider}' after proxy deletion"
                    )

                response.status = 200
                response.content_type = "application/json; charset=utf-8"
                return {
                    "success": True,
                    "provider": provider,
                    "message": message,
                    "reinitialized": reinit_success,
                }
            else:
                # Determine appropriate status code
                if "not registered" in message.lower():
                    response.status = 404
                else:
                    response.status = 500

                return {"error": message}

        except Exception as api_err:
            logger.error(
                f"API Error in DELETE /api/providers/{provider}/proxy: {str(api_err)}"
            )
            response.status = 500
            return {"error": f"Internal server error: {str(api_err)}"}

    @app.route("/api/providers/<provider>/reinitialize", method="POST")
    def reinitialize_provider(provider):
        """
        Manually reinitialize a provider (e.g., after external configuration changes)

        Example: POST /api/providers/joyn_de/reinitialize
        """
        try:
            success = manager.reinitialize_provider(provider)

            if success:
                return {
                    "success": True,
                    "provider": provider,
                    "message": f"Provider {provider} reinitialized successfully",
                }
            else:
                response.status = 500
                return {
                    "success": False,
                    "provider": provider,
                    "message": f"Failed to reinitialize provider {provider}",
                }

        except Exception as e:
            logger.error(f"Error reinitializing provider {provider}: {e}")
            response.status = 500
            return {"error": f"Internal server error: {str(e)}"}

    @app.route("/api/providers/<provider>/subscription")
    def get_provider_subscription(provider):
        """Get subscription status for a provider"""
        try:
            subscription = manager.get_subscription_status(provider)

            if subscription:
                return {"success": True, "subscription": subscription.to_dict()}
            else:
                return {
                    "success": True,
                    "subscription": None,
                    "message": "No subscription information available",
                }

        except ValueError as val_err:
            response.status = 404
            return {"error": str(val_err)}
        except Exception as api_err:
            logger.error(f"API Error in subscription endpoint: {str(api_err)}")
            response.status = 500
            return {"error": f"Internal server error: {str(api_err)}"}

    @app.route("/api/providers/<provider>/channels/subscribed")
    def get_subscribed_channels(provider):
        """Get channels the user is subscribed to for a provider"""
        try:
            channels = manager.get_subscribed_channels(provider)

            # Get provider instance for additional info
            provider_instance = manager.get_provider(provider)
            provider_catchup_hours = (
                getattr(provider_instance, "catchup_window", 0)
                if provider_instance
                else 0
            )

            channels_data = []
            for c in channels:
                channel_dict = c.to_dict()

                # Add catchup hours
                if hasattr(c, "catchup_hours"):
                    channel_dict["CatchupHours"] = c.catchup_hours
                else:
                    channel_dict["CatchupHours"] = provider_catchup_hours

                channels_data.append(channel_dict)

            return {
                "provider": provider,
                "channels": channels_data,
                "count": len(channels_data),
                "is_filtered": True,  # Indicates subscription filtering was applied
            }

        except ValueError as val_err:
            response.status = 404
            return {"error": str(val_err)}
        except Exception as api_err:
            logger.error(f"API Error in subscribed channels endpoint: {str(api_err)}")
            response.status = 500
            return {"error": f"Internal server error: {str(api_err)}"}

    @app.route("/api/providers/<provider>/packages")
    def get_provider_packages(provider):
        """Get available subscription packages for a provider"""
        try:
            packages = manager.get_available_packages(provider)

            return {
                "success": True,
                "provider": provider,
                "packages": [
                    {
                        "package_id": pkg.package_id,
                        "name": pkg.name,
                        "description": pkg.description,
                        "price_info": pkg.price_info,
                        "channel_count": pkg.channel_count,
                        "metadata": pkg.metadata,
                    }
                    for pkg in packages
                ],
                "count": len(packages),
            }

        except ValueError as val_err:
            response.status = 404
            return {"error": str(val_err)}
        except Exception as api_err:
            logger.error(f"API Error in packages endpoint: {str(api_err)}")
            response.status = 500
            return {"error": f"Internal server error: {str(api_err)}"}

    @app.route("/api/providers/channels/subscribed")
    def get_all_subscribed_channels():
        """Get all subscribed channels across all providers"""
        try:
            all_subscribed = {}
            provider_list = manager.list_providers()

            for provider in provider_list:
                try:
                    channels = manager.get_subscribed_channels(provider)
                    if channels:
                        all_subscribed[provider] = [c.to_dict() for c in channels]
                except Exception as provider_err:
                    logger.warning(
                        f"Could not get subscribed channels for {provider}: {provider_err}"
                    )
                    continue

            total_channels = sum(len(channels) for channels in all_subscribed.values())

            return {
                "success": True,
                "providers": list(all_subscribed.keys()),
                "channels_by_provider": all_subscribed,
                "total_channels": total_channels,
                "provider_count": len(all_subscribed),
            }

        except Exception as api_err:
            logger.error(
                f"API Error in all subscribed channels endpoint: {str(api_err)}"
            )
            response.status = 500
            return {"error": f"Internal server error: {str(api_err)}"}

    @app.route("/api/providers/<provider>/enabled", method="GET")
    def get_provider_enabled(provider):
        """Get enabled status for specific provider"""
        try:
            # Validate provider exists
            if not manager.get_provider(provider):
                response.status = 404
                return {"error": f"Provider {provider} not found"}

            from streaming_providers.base.settings.provider_enable_manager import (
                ProviderEnableManager,
            )

            enable_manager = ProviderEnableManager()
            status = enable_manager.is_provider_enabled(provider)
            source = enable_manager.get_enabled_source(provider)

            # FIX: Convert enum to string value
            source_value = source.value if hasattr(source, "value") else str(source)

            return {
                "success": True,
                "provider": provider,
                "enabled": status,
                "source": source_value,  # Now a string
                "can_modify": source != "kodi",
            }

        except Exception as e:
            logger.error(f"Error getting enabled status for {provider}: {e}")
            response.status = 500
            return {"error": str(e)}

    @app.route("/api/providers/<provider>/enabled", method="POST")
    def set_provider_enabled(provider):
        """Set enabled status for provider"""
        try:
            # Parse request
            try:
                data = request.json
                if not data or "enabled" not in data:
                    response.status = 400
                    return {"error": 'Missing "enabled" field'}

                enabled = bool(data["enabled"])
            except ValueError:
                response.status = 400
                return {"error": "Invalid JSON"}

            # Use the new manager method
            success = manager.set_provider_enabled(provider, enabled)

            if success:
                # Get updated metadata
                metadata = None
                all_metadata = manager.get_all_providers_metadata()
                for md in all_metadata:
                    if md["name"] == provider:
                        metadata = md
                        break

                return {
                    "success": True,
                    "provider": provider,
                    "enabled": enabled,
                    "metadata": metadata,
                    "message": f'Provider {provider} {"enabled" if enabled else "disabled"}',
                }
            else:
                response.status = 500
                return {
                    "error": f'Failed to {"enable" if enabled else "disable"} provider {provider}'
                }

        except Exception as e:
            logger.error(f"Error setting enabled status for {provider}: {e}")
            response.status = 500
            return {"error": str(e)}
