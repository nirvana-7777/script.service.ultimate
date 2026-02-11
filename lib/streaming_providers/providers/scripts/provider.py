# streaming_providers/providers/scripts/provider.py
# -*- coding: utf-8 -*-
"""
Scripts Provider Implementation

Executes Python scripts that implement streaming provider logic.
Each script must support actions: channels, manifest, cdm

Environment Variable:
    SCRIPTS_PROVIDERS_PATH: Directory containing provider scripts (auto-discovers *.py files)
"""

import json
import os
import re
import subprocess
import sys
import time
from typing import ClassVar, Dict, List, Optional, Any

from ...base.models.drm_models import DRMConfig, DRMSystem, LicenseConfig
from ...base.models.proxy_models import ProxyConfig
from ...base.models.streaming_channel import StreamingChannel
from ...base.provider import StreamingProvider
from ...base.utils.logger import logger
from ...base.utils.vfs import get_vfs
from .constants import (
    ACTION_CHANNELS,
    ACTION_MANIFEST,
    ACTION_CDM,
    AUTO_REFRESH_ON_EXPIRE,
    CHANNELS_CACHE_TTL,
    CDM_CACHE_TTL,
    CHANNEL_FIELD_MAPPING,
    DEFAULT_CHANNEL_CONFIG,
    DEFAULT_COUNTRY,
    DEFAULT_ENCODING,
    DEFAULT_DRM_SYSTEM,
    DEFAULT_LANGUAGE,
    DEFAULT_SCRIPT_TIMEOUT,
    ENV_SCRIPTS_PROVIDERS_PATH,
    ERROR_SCRIPT_NOT_FOUND,
    ERROR_SCRIPT_TIMEOUT,
    ERROR_INVALID_JSON,
    ERROR_CHANNELS_MISSING_FIELD,
    ERROR_MANIFEST_MISSING_FIELD,
    ERROR_CDM_INVALID_FORMAT,
    EXCLUDED_FILENAMES,
    MAX_OUTPUT_SIZE,
    PROXY_ARG_FORMAT,
    REQUIRED_CHANNEL_FIELDS,
    REQUIRED_MANIFEST_FIELDS,
    SCRIPTS_LOGO,
    SKIP_INVALID_CHANNELS,
    SUPPORTED_EXTENSIONS,
    # Import the new exception classes
    ScriptNotFoundError,
    ScriptTimeoutError,
    ScriptExecutionError,
    InvalidScriptOutputError,
)


class ScriptsProvider(StreamingProvider):
    """
    Scripts Provider

    Executes Python scripts that provide streaming functionality.
    Each script in the configured directory becomes a provider instance.
    """

    # ============================================================================
    # STATIC METADATA
    # ============================================================================
    PROVIDER_LABEL: ClassVar[str] = "Scripts Provider"
    SUPPORTED_AUTH_TYPES: ClassVar[List[str]] = ["anonymous"]  # Auth handled internally
    PROVIDER_LOGO: ClassVar[str] = SCRIPTS_LOGO
    SUPPORTED_COUNTRIES: ClassVar[List[str]] = ["*"]  # All countries

    def __init__(
            self,
            country: str = DEFAULT_COUNTRY,
            config_dir: Optional[str] = None,
            script_filename: Optional[str] = None,
            proxy_config: Optional[ProxyConfig] = None,
            proxy_url: Optional[str] = None,
            script_timeout: int = DEFAULT_SCRIPT_TIMEOUT,
            channels_cache_ttl: int = CHANNELS_CACHE_TTL,
            cdm_cache_ttl: int = CDM_CACHE_TTL,
            auto_refresh: bool = AUTO_REFRESH_ON_EXPIRE,
            encoding: str = DEFAULT_ENCODING,
            script_args: Optional[Dict[str, str]] = None,
    ):
        """
        Initialize Scripts provider

        Args:
            country: Country code (default: XX for international)
            config_dir: Configuration directory path
            script_filename: Specific script filename (if None, auto-discovers all *.py files)
            proxy_config: Proxy configuration object
            proxy_url: Proxy URL string
            script_timeout: Timeout in seconds for script execution
            channels_cache_ttl: Cache TTL for channels list in seconds
            cdm_cache_ttl: Cache TTL for DRM keys in seconds
            auto_refresh: Auto-refresh cache when expired
            encoding: File encoding for reading scripts
            script_args: Additional static arguments to pass to scripts

        Environment Variables:
            SCRIPTS_PROVIDERS_PATH: Directory containing script files (overrides config_dir)
        """
        super().__init__(country=country)

        # Store script filename - this determines provider identity
        self.script_filename = script_filename
        self.script_timeout = script_timeout
        self.channels_cache_ttl = channels_cache_ttl
        self.cdm_cache_ttl = cdm_cache_ttl
        self.auto_refresh = auto_refresh
        self.encoding = encoding
        self.script_args = script_args or {}

        # Determine scripts directory from environment or config_dir
        scripts_path = os.environ.get(ENV_SCRIPTS_PROVIDERS_PATH)
        if scripts_path:
            logger.info(f"Scripts: Using {ENV_SCRIPTS_PROVIDERS_PATH} from environment: {scripts_path}")
            self.scripts_dir = scripts_path
        elif config_dir:
            self.scripts_dir = config_dir
        else:
            # Use current directory as fallback
            self.scripts_dir = "."
            logger.warning(
                "Scripts: No SCRIPTS_PROVIDERS_PATH or config_dir specified, using current directory"
            )

        # Initialize VFS for file operations
        self.vfs = get_vfs(config_dir=self.scripts_dir)

        # Setup HTTP manager (minimal, scripts handle their own networking)
        self.http_manager = self._setup_http_manager(
            provider_name=self._get_base_provider_name(),
            proxy_config=proxy_config,
            proxy_url=proxy_url,
            config_dir=config_dir,
        )

        # Internal state and caching
        self._channels_cache: List[StreamingChannel] = []
        self._channels_cache_timestamp: float = 0
        self._cdm_cache: Dict[str, DRMConfig] = {}  # channel_id -> DRMConfig
        self._cdm_cache_timestamps: Dict[str, float] = {}

        # Statistics
        self._stats = {
            "script_executions": 0,
            "script_failures": 0,
            "channels_parsed": 0,
            "channels_skipped": 0,
            "drm_configs_loaded": 0,
            "cache_hits": 0,
            "cache_misses": 0,
        }

        # Validate script exists if specific filename provided
        if self.script_filename:
            self._validate_script()

    # ============================================================================
    # STATIC METHODS FOR DISCOVERY
    # ============================================================================

    @staticmethod
    def _get_base_provider_name() -> str:
        """Get base provider name (always 'scripts') for internal use"""
        return "scripts"

    @property
    def provider_name(self) -> str:
        """
        Provider name is the script filename without extension

        Examples:
            - "discoveryplus.py" -> "discoveryplus"
            - "dplay.py" -> "dplay"
            - "peacock_us.py" -> "peacock_us"
        """
        if self.script_filename:
            # Remove extension
            name = os.path.splitext(self.script_filename)[0]
            # Clean name for provider identifier
            clean_name = re.sub(r'[^a-z0-9_]+', '', name.lower())
            return clean_name if clean_name else "script"
        return "scripts"

    @property
    def provider_label(self) -> str:
        """
        Provider label is the script filename (human readable)

        Examples:
            - "discoveryplus.py" -> "Discoveryplus"
            - "dplay.py" -> "Dplay"
            - "peacock_us.py" -> "Peacock Us"
        """
        if self.script_filename:
            # Convert filename to nice label
            name = os.path.splitext(self.script_filename)[0]
            # Replace underscores with spaces and title case
            label = name.replace('_', ' ').title()
            return label
        return self.PROVIDER_LABEL

    @property
    def provider_logo(self) -> str:
        return self.PROVIDER_LOGO

    @property
    def supported_auth_types(self) -> List[str]:
        return self.SUPPORTED_AUTH_TYPES

    @property
    def uses_dynamic_manifests(self) -> bool:
        return True  # Scripts always generate manifests on demand

    @property
    def implements_epg(self) -> bool:
        return False  # Scripts don't implement EPG

    # ============================================================================
    # SCRIPT DISCOVERY
    # ============================================================================

    def _validate_script(self) -> bool:
        """Validate that the configured script exists and is readable"""
        if not self.script_filename:
            return False

        if not self.vfs.exists(self.script_filename):
            logger.error(f"Scripts: Script not found: {self.script_filename}")
            return False

        return True

    @classmethod
    def discover_scripts(cls, config_dir: Optional[str] = None) -> List[str]:
        """
        Discover all Python scripts in the scripts directory

        This is used for dynamic provider registration - each script becomes a provider.

        Args:
            config_dir: Configuration directory path

        Returns:
            List of script filenames (without directory) that can be providers
        """
        try:
            # Determine scripts directory
            scripts_path = os.environ.get(ENV_SCRIPTS_PROVIDERS_PATH)
            if scripts_path:
                scripts_dir = scripts_path
            elif config_dir:
                scripts_dir = config_dir
            else:
                scripts_dir = "."

            # Initialize VFS
            vfs = get_vfs(config_dir=scripts_dir)

            # Discover all Python files
            discovered = []
            for ext in SUPPORTED_EXTENSIONS:
                files = vfs.list_files("", pattern=f"*{ext}")
                discovered.extend(files)

            # Remove duplicates and sort
            discovered = sorted(set(discovered))

            # Filter out excluded filenames
            discovered = [
                f for f in discovered
                if os.path.basename(f) not in EXCLUDED_FILENAMES
                   and not os.path.basename(f).startswith('_')
            ]

            if not discovered:
                logger.debug(f"Scripts: No provider scripts found in {scripts_dir}")
            else:
                logger.info(f"Scripts: Discovered {len(discovered)} provider scripts: {', '.join(discovered)}")

            return discovered

        except Exception as e:
            logger.error(f"Scripts: Error during script discovery: {e}")
            return []

    # ============================================================================
    # SCRIPT EXECUTION
    # ============================================================================

    def _build_script_command(
            self,
            action: str,
            proxy_url: Optional[str] = None,
            timeout: Optional[int] = None,
            **kwargs,
    ) -> List[str]:
        """
        Build command line for script execution

        Args:
            action: Action to perform ('channels', 'manifest', 'cdm')
            proxy_url: Optional proxy URL string
            timeout: Optional custom timeout (uses self.script_timeout if None)
            **kwargs: Additional parameters to pass to script

        Returns:
            List of command arguments
        """
        if not self.script_filename:
            raise ValueError("No script filename configured")

        # Get full path to script
        script_path = self.vfs.join_path(self.script_filename)

        # Base command
        cmd = [sys.executable, script_path, "--action", action]

        # Add proxy if provided
        if proxy_url:
            cmd.append(PROXY_ARG_FORMAT.format(proxy_url))

        # Add all kwargs as --key=value arguments
        for key, value in kwargs.items():
            if value is not None:
                # Convert value to string and escape if needed
                cmd.append(f"--{key}={value}")

        # Add static script args (these come last and shouldn't override user kwargs)
        for key, value in self.script_args.items():
            if key not in kwargs:  # Only add if not already provided
                cmd.append(f"--{key}={value}")

        return cmd

    def _execute_script(
            self,
            action: str,
            proxy_url: Optional[str] = None,
            timeout: Optional[int] = None,
            **kwargs,
    ) -> Optional[Dict[str, Any]]:
        """
        Execute a script with the given action and parameters

        Args:
            action: Action to perform
            proxy_url: Optional proxy URL
            timeout: Optional custom timeout (uses self.script_timeout if None)
            **kwargs: Additional parameters

        Returns:
            Parsed JSON output as dict, or None if execution failed
        """
        if not self._validate_script():
            logger.error(ERROR_SCRIPT_NOT_FOUND.format(filename=self.script_filename))
            return None

        cmd = self._build_script_command(action, proxy_url, timeout, **kwargs)
        execution_timeout = timeout if timeout is not None else self.script_timeout

        logger.debug(f"Scripts: Executing {self.provider_label}: {' '.join(cmd)}")

        try:
            # Execute script with timeout
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=execution_timeout,
                check=False,
                encoding='utf-8',  # Explicitly set encoding
                errors='replace',  # Replace invalid characters instead of failing
            )

            self._stats["script_executions"] += 1

            # Check exit code
            if result.returncode != 0:
                self._stats["script_failures"] += 1
                stderr = result.stderr.strip() if result.stderr else "No error output"
                logger.error(
                    f"Scripts: {self.provider_label} - "
                    f"Script failed (exit code {result.returncode}): {stderr}"
                )
                return None

            # Check stdout size
            if len(result.stdout) > MAX_OUTPUT_SIZE:
                logger.error(
                    f"Scripts: {self.provider_label} - "
                    f"Output exceeds maximum size ({len(result.stdout)} > {MAX_OUTPUT_SIZE})"
                )
                return None

            # Parse JSON output
            try:
                output = json.loads(result.stdout)
                return output
            except json.JSONDecodeError as e:
                self._stats["script_failures"] += 1
                logger.error(ERROR_INVALID_JSON.format(error=e))
                logger.debug(f"Scripts: Raw output: {result.stdout[:500]}")
                return None

        except subprocess.TimeoutExpired:
            self._stats["script_failures"] += 1
            logger.error(ERROR_SCRIPT_TIMEOUT.format(
                timeout=execution_timeout,
                filename=self.script_filename
            ))
            return None
        except Exception as e:
            self._stats["script_failures"] += 1
            logger.error(f"Scripts: {self.provider_label} - Unexpected error: {e}")
            return None

    # ============================================================================
    # CHANNEL PARSING
    # ============================================================================

    def _parse_channels_output(self, output: Dict[str, Any]) -> List[StreamingChannel]:
        """
        Parse script output for action=channels into StreamingChannel objects

        Expected output format:
        {
            "Channels": [
                {
                    "Name": "Channel Name",
                    "Id": "channel_id",  # optional
                    "Mode": "live",
                    "SessionManifest": True,
                    "ManifestScript": "chanid=123",
                    "CdmType": "widevine",
                    "UseCdm": True,
                    "Cdm": "chanid=123",
                    ...
                }
            ]
        }

        Args:
            output: Parsed JSON output from script

        Returns:
            List of StreamingChannel objects
        """
        channels = []

        # Extract Channels array
        channels_data = output.get("Channels", [])
        if not isinstance(channels_data, list):
            logger.warning(f"Scripts: {self.provider_label} - 'Channels' is not a list")
            return []

        for idx, channel_data in enumerate(channels_data):
            try:
                # Skip invalid channels
                if not isinstance(channel_data, dict):
                    logger.warning(f"Scripts: {self.provider_label} - Channel {idx} is not a dict")
                    continue

                # Check required fields
                missing_fields = []
                for field in REQUIRED_CHANNEL_FIELDS:
                    if field not in channel_data:
                        missing_fields.append(field)

                if missing_fields:
                    if SKIP_INVALID_CHANNELS:
                        logger.warning(ERROR_CHANNELS_MISSING_FIELD.format(
                            field=", ".join(missing_fields),
                            name=channel_data.get("Name", f"channel_{idx}")
                        ))
                        self._stats["channels_skipped"] += 1
                        continue

                # Map fields to StreamingChannel format
                mapped_data = {
                    "provider": self.provider_name,
                    "country": self.country,
                    "language": DEFAULT_LANGUAGE,
                }

                # Apply field mapping
                for script_field, channel_field in CHANNEL_FIELD_MAPPING.items():
                    if script_field in channel_data:
                        mapped_data[channel_field] = channel_data[script_field]

                # Generate channel_id if not present
                if "channel_id" not in mapped_data:
                    mapped_data["channel_id"] = self._generate_channel_id(
                        mapped_data.get("name", "unknown"),
                        idx + 1,
                        self.script_filename or "script"
                    )

                # Apply default config
                for key, value in DEFAULT_CHANNEL_CONFIG.items():
                    if key not in mapped_data:
                        mapped_data[key] = value

                # Create channel object
                channel = StreamingChannel(**mapped_data)
                channels.append(channel)
                self._stats["channels_parsed"] += 1

            except Exception as e:
                logger.error(f"Scripts: {self.provider_label} - Error parsing channel {idx}: {e}")
                self._stats["channels_skipped"] += 1

        return channels

    @staticmethod
    def _generate_channel_id(name: str, index: int, script_name: str) -> str:
        """Generate a unique channel ID from name and script"""
        # Clean name: lowercase, remove special chars, replace spaces with underscores
        clean_name = re.sub(r"[^a-z0-9\s]", "", name.lower())
        clean_name = re.sub(r"\s+", "_", clean_name.strip())

        # Clean script name
        clean_script = re.sub(r"[^a-z0-9]", "_", script_name.lower())
        clean_script = clean_script.replace(".py", "")

        return f"{clean_script}_{clean_name}_{index}"

    # ============================================================================
    # DRM PARSING
    # ============================================================================

    def _parse_cdm_output(
            self,
            output: Dict[str, Any],
            channel_id: str,
    ) -> Optional[DRMConfig]:
        """
        Parse script output for action=cdm into DRMConfig

        Expected output format:
        {
            "keyids": {
                "0123456789abcdef0123456789abcdef": "fedcba9876543210fedcba9876543210",
                ...
            },
            "system": "widevine"  # optional, defaults to widevine
        }

        Or list of hex pairs:
        [
            "0123456789abcdef0123456789abcdef:fedcba9876543210fedcba9876543210",
            ...
        ]

        Args:
            output: Parsed JSON output from script
            channel_id: Channel ID for logging

        Returns:
            DRMConfig object or None
        """
        try:
            keyids = {}
            drm_system = DEFAULT_DRM_SYSTEM

            # Case 1: Dictionary format with keyids
            if isinstance(output, dict):
                # Extract system if present
                if "system" in output:
                    drm_system = output["system"].lower()

                # Extract keyids
                if "keyids" in output and isinstance(output["keyids"], dict):
                    for kid, key in output["keyids"].items():
                        # Clean hex strings (remove dashes and spaces)
                        kid_clean = kid.lower().replace("-", "").replace(" ", "")
                        key_clean = key.lower().replace("-", "").replace(" ", "")

                        # Validate 128-bit hex (32 chars)
                        if len(kid_clean) == 32 and all(c in "0123456789abcdef" for c in kid_clean):
                            if len(key_clean) == 32 and all(c in "0123456789abcdef" for c in key_clean):
                                keyids[kid_clean] = key_clean
                            else:
                                logger.warning(f"Scripts: {self.provider_label} - Invalid key hex: {key}")
                        else:
                            logger.warning(f"Scripts: {self.provider_label} - Invalid KID hex: {kid}")

            # Case 2: List format with "KID:KEY" pairs
            elif isinstance(output, list):
                for item in output:
                    if isinstance(item, str) and ":" in item:
                        kid, key = item.split(":", 1)
                        kid = kid.lower().replace("-", "").replace(" ", "")
                        key = key.lower().replace("-", "").replace(" ", "")

                        if len(kid) == 32 and all(c in "0123456789abcdef" for c in kid):
                            if len(key) == 32 and all(c in "0123456789abcdef" for c in key):
                                keyids[kid] = key
                            else:
                                logger.warning(ERROR_CDM_INVALID_FORMAT.format(line=item))
                        else:
                            logger.warning(ERROR_CDM_INVALID_FORMAT.format(line=item))
                    else:
                        logger.warning(ERROR_CDM_INVALID_FORMAT.format(line=str(item)))

            if not keyids:
                logger.debug(f"Scripts: {self.provider_label} - No valid keys found for channel {channel_id}")
                return None

            # Resolve DRM system
            drm_system_enum = DRMSystem.from_alias(drm_system) or DRMSystem.WIDEVINE

            # Create DRM config
            license_config = LicenseConfig(
                keyids=keyids,
            )

            drm_config = DRMConfig(
                system=drm_system_enum,
                license=license_config,
            )

            self._stats["drm_configs_loaded"] += 1
            logger.debug(f"Scripts: {self.provider_label} - Loaded {len(keyids)} keys for {channel_id}")

            return drm_config

        except Exception as e:
            logger.error(f"Scripts: {self.provider_label} - Error parsing CDM output: {e}")
            return None

    # ============================================================================
    # CHANNEL MANAGEMENT
    # ============================================================================

    def _should_refresh_channels_cache(self) -> bool:
        """Check if channels cache should be refreshed"""
        if not self._channels_cache:
            return True

        if self.auto_refresh:
            age = time.time() - self._channels_cache_timestamp
            return age >= self.channels_cache_ttl

        return False

    def _should_refresh_cdm_cache(self, channel_id: str) -> bool:
        """Check if CDM cache for a channel should be refreshed"""
        if channel_id not in self._cdm_cache:
            return True

        if self.auto_refresh:
            age = time.time() - self._cdm_cache_timestamps.get(channel_id, 0)
            return age >= self.cdm_cache_ttl

        return False

    def get_channels(
            self,
            fetch_manifests: bool = False,
            populate_streaming_data: bool = True,
            force_refresh: bool = False,
            proxy_url: Optional[str] = None,
            **kwargs,
    ) -> List[StreamingChannel]:
        """
        Get channels by executing script with action=channels

        Args:
            fetch_manifests: Not used (manifests are generated on demand)
            populate_streaming_data: Not used (data comes from script)
            force_refresh: Force re-execution of script
            proxy_url: Optional proxy URL to pass to script
            **kwargs: Additional arguments passed to script

        Returns:
            List of StreamingChannel objects
        """
        # Check cache
        if not force_refresh and not self._should_refresh_channels_cache():
            if self._channels_cache:
                self._stats["cache_hits"] += 1
                logger.debug(f"Scripts ({self.provider_label}): Returning channels from cache")
                return self._channels_cache.copy()

        self._stats["cache_misses"] += 1
        logger.info(f"Scripts ({self.provider_label}): Executing script to fetch channels...")

        # Execute script
        output = self._execute_script(
            action=ACTION_CHANNELS,
            proxy_url=proxy_url,
            **kwargs,
        )

        if not output:
            # Return cached data if available, otherwise empty list
            if self._channels_cache:
                logger.warning(f"Scripts ({self.provider_label}): Script failed, using stale cache")
                return self._channels_cache.copy()
            return []

        # Parse channels
        channels = self._parse_channels_output(output)

        # Update cache
        self._channels_cache = channels
        self._channels_cache_timestamp = time.time()

        logger.info(
            f"Scripts ({self.provider_label}): Loaded {len(channels)} channels "
            f"(parsed: {self._stats['channels_parsed']}, skipped: {self._stats['channels_skipped']})"
        )

        return channels

    def get_manifest(
            self,
            channel_id: str,
            proxy_url: Optional[str] = None,
            **kwargs,
    ) -> Optional[str]:
        """
        Get manifest URL for a specific channel by executing script with action=manifest

        Args:
            channel_id: Channel identifier
            proxy_url: Optional proxy URL to pass to script
            **kwargs: Additional arguments passed to script (merged with channel manifest script)

        Returns:
            Manifest URL string or None
        """
        # Find channel to get manifest script parameters
        channel = None
        channels = self.get_channels()
        for ch in channels:
            if ch.channel_id == channel_id:
                channel = ch
                break

        if not channel:
            logger.warning(f"Scripts ({self.provider_label}): Channel not found: {channel_id}")
            return None

        # Parse manifest script parameters
        manifest_params = {}
        if channel.manifest_script:
            # Parse key=value pairs
            for param in channel.manifest_script.split("&"):
                if "=" in param:
                    key, value = param.split("=", 1)
                    manifest_params[key] = value

        # Merge with provided kwargs (kwargs take precedence)
        script_kwargs = {**manifest_params, **kwargs}

        # Execute script
        output = self._execute_script(
            action=ACTION_MANIFEST,
            proxy_url=proxy_url,
            **script_kwargs,
        )

        if not output:
            return None

        # Validate required fields
        for field in REQUIRED_MANIFEST_FIELDS:
            if field not in output:
                logger.error(ERROR_MANIFEST_MISSING_FIELD.format(field=field))
                return None

        # Extract manifest URL
        manifest_url = output.get("ManifestUrl")
        if not manifest_url:
            logger.error("Scripts: ManifestUrl is empty")
            return None

        # Note: Headers and Heartbeat are stored in the channel/drm config
        # This is handled by the player, not the provider

        return manifest_url

    def get_drm(
            self,
            channel_id: str,
            proxy_url: Optional[str] = None,
            force_refresh: bool = False,
            **kwargs,
    ) -> List[DRMConfig]:
        """
        Get DRM configuration for a specific channel

        Args:
            channel_id: Channel identifier
            proxy_url: Optional proxy URL to pass to script
            force_refresh: Force re-fetching of DRM keys
            **kwargs: Additional arguments passed to script

        Returns:
            List of DRMConfig objects (empty if no DRM)
        """
        # Find channel to get CDM parameters
        channel = None
        channels = self.get_channels()
        for ch in channels:
            if ch.channel_id == channel_id:
                channel = ch
                break

        if not channel:
            logger.warning(f"Scripts ({self.provider_label}): Channel not found: {channel_id}")
            return []

        # Check cache
        if not force_refresh and not self._should_refresh_cdm_cache(channel_id):
            cached_config = self._cdm_cache.get(channel_id)
            if cached_config:
                self._stats["cache_hits"] += 1
                logger.debug(f"Scripts ({self.provider_label}): Returning DRM config from cache for {channel_id}")
                return [cached_config]

        self._stats["cache_misses"] += 1

        # Parse CDM parameters from channel
        cdm_params = {}
        if channel.cdm:
            # Parse key=value pairs
            for param in channel.cdm.split("&"):
                if "=" in param:
                    key, value = param.split("=", 1)
                    cdm_params[key] = value

        # Merge with provided kwargs
        script_kwargs = {**cdm_params, **kwargs}

        # Execute script
        output = self._execute_script(
            action=ACTION_CDM,
            proxy_url=proxy_url,
            **script_kwargs,
        )

        if not output:
            return []

        # Parse DRM config
        drm_config = self._parse_cdm_output(output, channel_id)

        if drm_config:
            # Update cache
            self._cdm_cache[channel_id] = drm_config
            self._cdm_cache_timestamps[channel_id] = time.time()
            return [drm_config]

        return []

    def enrich_channel_data(
            self,
            channel: StreamingChannel,
            **kwargs,
    ) -> Optional[StreamingChannel]:
        """
        Scripts provider channels are already fully populated

        Returns:
            Same channel object
        """
        return channel

    def get_dynamic_manifest_params(
            self,
            channel: StreamingChannel,
            **kwargs,
    ) -> Optional[str]:
        """
        Get manifest script parameters for a channel

        Returns:
            Manifest script string or None
        """
        return channel.manifest_script if channel.session_manifest else None

    # ============================================================================
    # UTILITY METHODS
    # ============================================================================

    def get_statistics(self) -> Dict[str, Any]:
        """Get execution statistics"""
        return {
            **self._stats,
            "script_filename": self.script_filename,
            "scripts_dir": self.scripts_dir,
            "channels_cache_age": time.time() - self._channels_cache_timestamp if self._channels_cache_timestamp else 0,
            "cached_channels": len(self._channels_cache),
            "cached_drm_configs": len(self._cdm_cache),
        }

    def test_script(self) -> Dict[str, Any]:
        """
        Test if script is executable and returns valid channels

        Returns:
            Test result dictionary
        """
        result: Dict[str, Any] = {
            "provider": self.provider_name,
            "label": self.provider_label,
            "script": self.script_filename,
            "scripts_dir": self.scripts_dir,
            "success": False,
            "script_exists": False,
            "script_executable": False,
            "channels_found": 0,
            "error": None,
        }

        try:
            # Check script exists
            if not self.script_filename:
                result["error"] = "No script filename configured"
                return result

            result["script_exists"] = self.vfs.exists(self.script_filename)

            if not result["script_exists"]:
                result["error"] = f"Script not found: {self.script_filename}"
                return result

            # Try to execute script with channels action
            output = self._execute_script(ACTION_CHANNELS, timeout=10)

            if output:
                result["script_executable"] = True

                # Parse channels
                channels = self._parse_channels_output(output)
                result["channels_found"] = len(channels)

                # Check if we got valid channels
                if channels:
                    result["success"] = True
                    result["sample_channels"] = [
                        {"name": c.name, "id": c.channel_id}
                        for c in channels[:5]  # First 5 channels as sample
                    ]
            else:
                result["error"] = "Script execution failed or returned no output"

        except Exception as e:
            result["error"] = str(e)

        result["statistics"] = self.get_statistics()
        return result

    def clear_caches(self) -> None:
        """Clear all caches"""
        self._channels_cache = []
        self._channels_cache_timestamp = 0
        self._cdm_cache.clear()
        self._cdm_cache_timestamps.clear()
        logger.info(f"Scripts ({self.provider_label}): Caches cleared")

    def close(self) -> None:
        """Clean up resources"""
        if hasattr(self, "http_manager") and self.http_manager:
            self.http_manager.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False