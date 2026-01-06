# streaming_providers/base/settings/models/provider_settings.py
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from ...utils.logger import logger
from .settings_models import (SettingValue, boolean_setting, integer_setting,
                              password_setting, port_setting, select_setting,
                              string_setting)


@dataclass
class ProviderSettingsSchema:
    """Schema definition for a provider's settings"""

    provider_name: str
    _settings: Dict[str, SettingValue] = field(default_factory=dict)
    _categories: Dict[str, Set[str]] = field(default_factory=dict)
    _kodi_mapping: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self):
        """Initialize schema with default settings"""
        self._build_default_schema()

    def _build_default_schema(self) -> None:
        """Build the complete settings schema for this provider"""
        # Build all setting categories
        credential_settings = self.define_credential_settings()
        proxy_settings = self.define_proxy_settings()
        video_settings = self.define_video_settings()
        drm_settings = self.define_drm_settings()
        network_settings = self.define_network_settings()

        # Merge all settings
        self._settings.update(credential_settings)
        self._settings.update(proxy_settings)
        self._settings.update(video_settings)
        self._settings.update(drm_settings)
        self._settings.update(network_settings)

        # Build category mappings
        self._categories = {
            "credentials": set(credential_settings.keys()),
            "proxy": set(proxy_settings.keys()),
            "video": set(video_settings.keys()),
            "drm": set(drm_settings.keys()),
            "network": set(network_settings.keys()),
        }

        # Build Kodi mapping
        self._build_kodi_mapping()

    def _build_kodi_mapping(self) -> None:
        """Build mapping from internal setting names to Kodi setting IDs"""
        for setting_name, setting in self._settings.items():
            if setting.kodi_setting_id:
                self._kodi_mapping[setting_name] = setting.kodi_setting_id

    def define_credential_settings(self) -> Dict[str, SettingValue]:
        """Define credential-related settings for this provider"""
        settings = {}

        # Common credential settings - can be overridden in subclasses
        settings["username"] = (
            string_setting()
            .required()
            .min_length(1)
            .display_name("Username")
            .description("Account username or email address")
            .kodi_setting(f"{self.provider_name}_username")
            .build()
        )

        settings["password"] = (
            password_setting()
            .display_name("Password")
            .description("Account password")
            .kodi_setting(f"{self.provider_name}_password")
            .build()
        )

        # Optional client ID for OAuth providers
        settings["client_id"] = (
            string_setting()
            .display_name("Client ID")
            .description("OAuth client identifier (if required)")
            .kodi_setting(f"{self.provider_name}_client_id")
            .build()
        )

        # Optional client secret for OAuth providers
        settings["client_secret"] = (
            password_setting(required=False)
            .display_name("Client Secret")
            .description("OAuth client secret (if required)")
            .kodi_setting(f"{self.provider_name}_client_secret")
            .build()
        )

        return settings

    def define_proxy_settings(self) -> Dict[str, SettingValue]:
        """Define proxy-related settings for this provider"""
        settings = {}

        # Enable proxy for this provider
        settings["proxy_enabled"] = (
            boolean_setting(False)
            .display_name("Enable Proxy")
            .description("Use proxy for this provider")
            .kodi_setting(f"{self.provider_name}_proxy_enabled")
            .build()
        )

        # Proxy host
        settings["proxy_host"] = (
            string_setting()
            .display_name("Proxy Host")
            .description("Proxy server hostname or IP address")
            .kodi_setting(f"{self.provider_name}_proxy_host")
            .build()
        )

        # Proxy port
        settings["proxy_port"] = (
            port_setting(8080)
            .display_name("Proxy Port")
            .description("Proxy server port")
            .kodi_setting(f"{self.provider_name}_proxy_port")
            .build()
        )

        # Proxy type
        settings["proxy_type"] = (
            select_setting(["http", "https", "socks4", "socks5"], "http")
            .display_name("Proxy Type")
            .description("Type of proxy server")
            .kodi_setting(f"{self.provider_name}_proxy_type")
            .build()
        )

        # Proxy authentication
        settings["proxy_auth_enabled"] = (
            boolean_setting(False)
            .display_name("Proxy Authentication")
            .description("Proxy server requires authentication")
            .kodi_setting(f"{self.provider_name}_proxy_auth_enabled")
            .build()
        )

        # Proxy username
        settings["proxy_username"] = (
            string_setting()
            .display_name("Proxy Username")
            .description("Username for proxy authentication")
            .kodi_setting(f"{self.provider_name}_proxy_username")
            .build()
        )

        # Proxy password
        settings["proxy_password"] = (
            password_setting(required=False)
            .display_name("Proxy Password")
            .description("Password for proxy authentication")
            .kodi_setting(f"{self.provider_name}_proxy_password")
            .build()
        )

        # Proxy scope settings
        settings["proxy_scope_api"] = (
            boolean_setting(True)
            .display_name("Proxy API Calls")
            .description("Use proxy for API requests")
            .kodi_setting(f"{self.provider_name}_proxy_scope_api")
            .build()
        )

        settings["proxy_scope_auth"] = (
            boolean_setting(True)
            .display_name("Proxy Authentication")
            .description("Use proxy for authentication requests")
            .kodi_setting(f"{self.provider_name}_proxy_scope_auth")
            .build()
        )

        settings["proxy_scope_manifest"] = (
            boolean_setting(True)
            .display_name("Proxy Manifests")
            .description("Use proxy for manifest downloads")
            .kodi_setting(f"{self.provider_name}_proxy_scope_manifest")
            .build()
        )

        settings["proxy_scope_license"] = (
            boolean_setting(True)
            .display_name("Proxy DRM Licenses")
            .description("Use proxy for DRM license requests")
            .kodi_setting(f"{self.provider_name}_proxy_scope_license")
            .build()
        )

        return settings

    def define_video_settings(self) -> Dict[str, SettingValue]:
        """Define video quality/format settings for this provider"""
        settings = {}

        # Video quality preference
        settings["video_quality"] = (
            select_setting(["best", "worst", "720p", "1080p", "4k"], "best")
            .display_name("Video Quality")
            .description("Preferred video quality")
            .kodi_setting(f"{self.provider_name}_video_quality")
            .build()
        )

        # Audio language preference
        settings["audio_language"] = (
            select_setting(["de", "en", "original"], "de")
            .display_name("Audio Language")
            .description("Preferred audio language")
            .kodi_setting(f"{self.provider_name}_audio_language")
            .build()
        )

        # Subtitle language preference
        settings["subtitle_language"] = (
            select_setting(["none", "de", "en", "auto"], "none")
            .display_name("Subtitle Language")
            .description("Preferred subtitle language")
            .kodi_setting(f"{self.provider_name}_subtitle_language")
            .build()
        )

        # Speed up streams
        settings["speed_up"] = (
            boolean_setting(True)
            .display_name("Speed Up Playback")
            .description("Enable faster stream startup")
            .kodi_setting(f"{self.provider_name}_speed_up")
            .build()
        )

        return settings

    def define_drm_settings(self) -> Dict[str, SettingValue]:
        """Define DRM/CDM related settings for this provider"""
        settings = {}

        # CDM usage
        settings["use_cdm"] = (
            boolean_setting(True)
            .display_name("Use CDM")
            .description("Enable Content Decryption Module for DRM")
            .kodi_setting(f"{self.provider_name}_use_cdm")
            .build()
        )

        # CDM type
        settings["cdm_type"] = (
            select_setting(["widevine", "playready", "clearkey"], "widevine")
            .display_name("CDM Type")
            .description("Type of Content Decryption Module")
            .kodi_setting(f"{self.provider_name}_cdm_type")
            .build()
        )

        # CDM mode
        settings["cdm_mode"] = (
            select_setting(["external", "internal", "auto"], "external")
            .display_name("CDM Mode")
            .description("How to handle CDM operations")
            .kodi_setting(f"{self.provider_name}_cdm_mode")
            .build()
        )

        return settings

    def define_network_settings(self) -> Dict[str, SettingValue]:
        """Define network timeout/retry settings for this provider"""
        settings = {}

        # Request timeout
        settings["request_timeout"] = (
            integer_setting(30, 5, 120)
            .display_name("Request Timeout")
            .description("Timeout for network requests in seconds")
            .kodi_setting(f"{self.provider_name}_request_timeout")
            .build()
        )

        # Max retries
        settings["max_retries"] = (
            integer_setting(3, 0, 10)
            .display_name("Max Retries")
            .description("Maximum number of retry attempts")
            .kodi_setting(f"{self.provider_name}_max_retries")
            .build()
        )

        # Retry delay
        settings["retry_delay"] = (
            integer_setting(1, 0, 10)
            .display_name("Retry Delay")
            .description("Delay between retry attempts in seconds")
            .kodi_setting(f"{self.provider_name}_retry_delay")
            .build()
        )

        # Verify SSL
        settings["verify_ssl"] = (
            boolean_setting(True)
            .display_name("Verify SSL")
            .description("Verify SSL certificates for HTTPS requests")
            .kodi_setting(f"{self.provider_name}_verify_ssl")
            .build()
        )

        return settings

    def get_all_settings(self) -> Dict[str, SettingValue]:
        """Get complete settings schema for this provider"""
        return self._settings.copy()

    def get_setting(self, setting_name: str) -> Optional[SettingValue]:
        """Get a specific setting by name"""
        return self._settings.get(setting_name)

    def get_settings_by_category(self, category: str) -> Dict[str, SettingValue]:
        """Get all settings in a specific category"""
        if category not in self._categories:
            return {}

        category_settings = {}
        for setting_name in self._categories[category]:
            if setting_name in self._settings:
                category_settings[setting_name] = self._settings[setting_name]

        return category_settings

    def get_categories(self) -> List[str]:
        """Get list of all setting categories"""
        return list(self._categories.keys())

    def get_kodi_setting_mapping(self) -> Dict[str, str]:
        """Get mapping from internal setting names to Kodi setting IDs"""
        return self._kodi_mapping.copy()

    def get_reverse_kodi_mapping(self) -> Dict[str, str]:
        """Get mapping from Kodi setting IDs to internal setting names"""
        return {v: k for k, v in self._kodi_mapping.items()}

    def validate_all_settings(self) -> Dict[str, tuple[bool, List[str]]]:
        """Validate all settings in the schema"""
        results = {}
        for setting_name, setting in self._settings.items():
            results[setting_name] = setting.validate()
        return results

    def get_required_settings(self) -> List[str]:
        """Get list of setting names that are required"""
        required = []
        for setting_name, setting in self._settings.items():
            # Check if setting has a "not_empty" validation rule
            has_required_rule = any(
                rule.name == "not_empty" for rule in setting.validation_rules
            )
            if has_required_rule:
                required.append(setting_name)
        return required

    def get_incomplete_settings(self) -> List[str]:
        """Get list of required settings that don't have values"""
        incomplete = []
        required_settings = self.get_required_settings()

        for setting_name in required_settings:
            setting = self._settings[setting_name]
            if not setting.has_value():
                incomplete.append(setting_name)

        return incomplete

    def is_configuration_complete(self) -> bool:
        """Check if all required settings have values"""
        return len(self.get_incomplete_settings()) == 0

    def get_configuration_completeness(self) -> Dict[str, Any]:
        """Get detailed information about configuration completeness"""
        required_settings = self.get_required_settings()
        incomplete_settings = self.get_incomplete_settings()

        completeness_by_category = {}
        for category in self.get_categories():
            category_settings = self.get_settings_by_category(category)
            category_required = [
                name for name in category_settings.keys() if name in required_settings
            ]
            category_incomplete = [
                name for name in category_settings.keys() if name in incomplete_settings
            ]

            completeness_by_category[category] = {
                "total_settings": len(category_settings),
                "required_settings": len(category_required),
                "incomplete_settings": len(category_incomplete),
                "is_complete": len(category_incomplete) == 0,
                "completion_percentage": (
                    100.0
                    if len(category_required) == 0
                    else (
                        (len(category_required) - len(category_incomplete))
                        / len(category_required)
                        * 100
                    )
                ),
            }

        return {
            "is_complete": self.is_configuration_complete(),
            "total_settings": len(self._settings),
            "required_settings": len(required_settings),
            "incomplete_settings": len(incomplete_settings),
            "completion_percentage": (
                100.0
                if len(required_settings) == 0
                else (
                    (len(required_settings) - len(incomplete_settings))
                    / len(required_settings)
                    * 100
                )
            ),
            "categories": completeness_by_category,
            "incomplete_setting_names": incomplete_settings,
        }

    def add_custom_setting(
        self, setting_name: str, setting: SettingValue, category: str = "custom"
    ) -> None:
        """Add a custom setting to the schema"""
        self._settings[setting_name] = setting

        if category not in self._categories:
            self._categories[category] = set()
        self._categories[category].add(setting_name)

        if setting.kodi_setting_id:
            self._kodi_mapping[setting_name] = setting.kodi_setting_id

    def remove_setting(self, setting_name: str) -> bool:
        """Remove a setting from the schema"""
        if setting_name not in self._settings:
            return False

        # Remove from settings
        del self._settings[setting_name]

        # Remove from categories
        for category_settings in self._categories.values():
            category_settings.discard(setting_name)

        # Remove from Kodi mapping
        if setting_name in self._kodi_mapping:
            del self._kodi_mapping[setting_name]

        return True

    def to_dict(self) -> Dict[str, Any]:
        """Convert schema to dictionary representation"""
        return {
            "provider_name": self.provider_name,
            "settings": {
                name: setting.to_dict() for name, setting in self._settings.items()
            },
            "categories": {
                category: list(settings)
                for category, settings in self._categories.items()
            },
            "kodi_mapping": self._kodi_mapping.copy(),
            "configuration_status": self.get_configuration_completeness(),
        }


class StandardProviderSettings:
    """Standard settings schemas for common providers"""

    _registered_schemas: Dict[str, ProviderSettingsSchema] = {}

    @classmethod
    def get_rtlplus_schema(cls) -> ProviderSettingsSchema:
        """Get RTL Plus settings schema"""
        if "rtlplus" not in cls._registered_schemas:
            schema = ProviderSettingsSchema("rtlplus")

            # RTL Plus specific customizations
            # Override default credential settings for RTL Plus specifics
            schema._settings["username"].description = "RTL Plus account email address"

            # Add RTL Plus specific settings
            schema.add_custom_setting(
                "device_id",
                string_setting()
                .display_name("Device ID")
                .description("Unique device identifier for RTL Plus")
                .kodi_setting("rtlplus_device_id")
                .build(),
                "credentials",
            )

            cls._registered_schemas["rtlplus"] = schema

        return cls._registered_schemas["rtlplus"]

    @classmethod
    def get_joyn_schema(cls) -> ProviderSettingsSchema:
        """Get Joyn settings schema"""
        if "joyn" not in cls._registered_schemas:
            schema = ProviderSettingsSchema("joyn")

            # Joyn doesn't require authentication for basic content
            schema._settings["username"].validation_rules = [
                rule
                for rule in schema._settings["username"].validation_rules
                if rule.name != "not_empty"
            ]
            schema._settings["password"].validation_rules = [
                rule
                for rule in schema._settings["password"].validation_rules
                if rule.name != "not_empty"
            ]

            cls._registered_schemas["joyn"] = schema

        return cls._registered_schemas["joyn"]

    @classmethod
    def get_zdf_schema(cls) -> ProviderSettingsSchema:
        """Get ZDF settings schema"""
        if "zdf" not in cls._registered_schemas:
            schema = ProviderSettingsSchema("zdf")

            # ZDF is free, no authentication required
            schema.remove_setting("username")
            schema.remove_setting("password")
            schema.remove_setting("client_id")
            schema.remove_setting("client_secret")

            # Add ZDF specific settings
            schema.add_custom_setting(
                "geo_location",
                select_setting(["DE", "AT", "CH"], "DE")
                .display_name("Geographic Location")
                .description("Your geographic location for content filtering")
                .kodi_setting("zdf_geo_location")
                .build(),
                "network",
            )

            cls._registered_schemas["zdf"] = schema

        return cls._registered_schemas["zdf"]

    @classmethod
    def get_ard_schema(cls) -> ProviderSettingsSchema:
        """Get ARD settings schema"""
        if "ard" not in cls._registered_schemas:
            schema = ProviderSettingsSchema("ard")

            # ARD is free, no authentication required
            schema.remove_setting("username")
            schema.remove_setting("password")
            schema.remove_setting("client_id")
            schema.remove_setting("client_secret")

            cls._registered_schemas["ard"] = schema

        return cls._registered_schemas["ard"]

    @classmethod
    def register_provider_schema(
        cls, provider_name: str, schema: ProviderSettingsSchema
    ) -> None:
        """Register a custom provider schema"""
        cls._registered_schemas[provider_name] = schema
        logger.info(f"Registered custom settings schema for provider: {provider_name}")

    @classmethod
    def get_provider_schema(
        cls, provider_name: str
    ) -> Optional[ProviderSettingsSchema]:
        """Get schema for a provider, creating default if not found"""
        # Check if we have a specific schema method
        method_name = f"get_{provider_name}_schema"
        if hasattr(cls, method_name):
            return getattr(cls, method_name)()

        # Check registered schemas
        if provider_name in cls._registered_schemas:
            return cls._registered_schemas[provider_name]

        # Create default schema
        logger.info(f"Creating default settings schema for provider: {provider_name}")
        schema = ProviderSettingsSchema(provider_name)
        cls._registered_schemas[provider_name] = schema
        return schema

    @classmethod
    def list_registered_providers(cls) -> List[str]:
        """Get list of all registered provider schemas"""
        # Include both registered schemas and built-in methods
        builtin_providers = []
        for attr_name in dir(cls):
            if (
                attr_name.startswith("get_")
                and attr_name.endswith("_schema")
                and attr_name != "get_provider_schema"
            ):
                provider_name = attr_name[4:-7]  # Remove 'get_' and '_schema'
                builtin_providers.append(provider_name)

        all_providers = list(
            set(builtin_providers + list(cls._registered_schemas.keys()))
        )
        return sorted(all_providers)

    @classmethod
    def unregister_provider_schema(cls, provider_name: str) -> bool:
        """Unregister a provider schema"""
        if provider_name in cls._registered_schemas:
            del cls._registered_schemas[provider_name]
            logger.info(f"Unregistered settings schema for provider: {provider_name}")
            return True
        return False
