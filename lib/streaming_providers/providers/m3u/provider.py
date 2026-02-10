# streaming_providers/providers/m3u/provider.py
# -*- coding: utf-8 -*-
"""
M3U Playlist Provider Implementation

Provides access to channels from local M3U/M3U8 playlist files
with support for extended attributes, DRM, and both DASH and HLS formats.

Environment Variable:
    M3U_PLAYLISTS_PATH: Directory containing M3U playlist files (auto-discovers *.m3u files)
"""

import os
import re
import time
from typing import ClassVar, Dict, List, Optional

from ...base.models.drm_models import DRMConfig, DRMSystem, LicenseConfig
from ...base.models.proxy_models import ProxyConfig
from ...base.models.streaming_channel import StreamingChannel
from ...base.provider import StreamingProvider
from ...base.utils.logger import logger
from ...base.utils.vfs import get_vfs
from .constants import (
    AUTO_REFRESH_ON_EXPIRE,
    CONTENT_TYPE_KEYWORDS,
    CUSTOM_ATTRIBUTES,
    DEFAULT_CACHE_TTL,
    DEFAULT_CHANNEL_CONFIG,
    DEFAULT_CONTENT_TYPE,
    DEFAULT_COUNTRY,
    DEFAULT_ENCODING,
    DEFAULT_LANGUAGE,
    DEFAULT_MAX_RETRIES,
    DEFAULT_PROVIDER_NAME,
    DEFAULT_QUALITY,
    DEFAULT_REQUEST_TIMEOUT,
    DEFAULT_STREAMING_FORMAT,
    DEFAULT_USER_AGENT,
    DRM_ATTRIBUTES,
    ENV_M3U_PLAYLISTS_PATH,
    EXTINF_PREFIX,
    FALLBACK_ENCODINGS,
    KODI_VLC_PROPERTIES,
    M3U_HEADER,
    M3U_LOGO,
    MANIFEST_PATTERNS,
    QUALITY_PATTERNS,
    REQUIRED_FIELDS,
    SKIP_INVALID_CHANNELS,
    SUPPORTED_EXTENSIONS,
    TVG_ATTRIBUTES,
    WARN_MISSING_OPTIONAL_FIELDS,
)


class M3UProvider(StreamingProvider):
    """
    M3U Playlist Provider

    Parses local M3U/M3U8 files to extract channel information including:
    - Channel metadata (name, logo, group, language, country)
    - Manifest URLs (DASH .mpd, HLS .m3u8)
    - DRM configuration (license URLs, keys)
    - Custom properties (Kodi/VLC options)
    """

    # ============================================================================
    # STATIC METADATA
    # ============================================================================
    PROVIDER_LABEL: ClassVar[str] = "M3U Playlist"
    SUPPORTED_AUTH_TYPES: ClassVar[List[str]] = ["anonymous"]
    PROVIDER_LOGO: ClassVar[str] = M3U_LOGO
    SUPPORTED_COUNTRIES: ClassVar[List[str]] = ["*"]  # All countries

    def __init__(
            self,
            country: str = DEFAULT_COUNTRY,
            config_dir: Optional[str] = None,
            m3u_filename: Optional[str] = None,
            proxy_config: Optional[ProxyConfig] = None,
            proxy_url: Optional[str] = None,
            cache_ttl: int = DEFAULT_CACHE_TTL,
            auto_refresh: bool = AUTO_REFRESH_ON_EXPIRE,
            encoding: str = DEFAULT_ENCODING,
    ):
        """
        Initialize M3U provider

        Args:
            country: Country code (default: XX for international)
            config_dir: Configuration directory path
            m3u_filename: Specific M3U filename (if None, auto-discovers all *.m3u files)
            proxy_config: Proxy configuration object
            proxy_url: Proxy URL string
            cache_ttl: Cache time-to-live in seconds
            auto_refresh: Auto-refresh playlist when cache expires
            encoding: File encoding (default: utf-8)

        Environment Variables:
            M3U_PLAYLISTS_PATH: Directory containing M3U files (overrides config_dir)
        """
        super().__init__(country=country)

        # Determine playlist directory from environment or config_dir
        playlists_path = os.environ.get(ENV_M3U_PLAYLISTS_PATH)
        if playlists_path:
            logger.info(f"M3U: Using {ENV_M3U_PLAYLISTS_PATH} from environment: {playlists_path}")
            self.playlists_dir = playlists_path
        elif config_dir:
            self.playlists_dir = config_dir
        else:
            # Use current directory as fallback
            self.playlists_dir = "."
            logger.warning(
                "M3U: No M3U_PLAYLISTS_PATH or config_dir specified, using current directory"
            )

        # Initialize VFS for file operations
        self.vfs = get_vfs(config_dir=self.playlists_dir)

        # Store configuration
        self.m3u_filename = m3u_filename
        self.encoding = encoding
        self.cache_ttl = cache_ttl
        self.auto_refresh = auto_refresh

        # Setup HTTP manager for potential future use
        self.http_manager = self._setup_http_manager(
            provider_name="m3u",
            proxy_config=proxy_config,
            proxy_url=proxy_url,
            config_dir=config_dir,
            user_agent=DEFAULT_USER_AGENT,
            timeout=DEFAULT_REQUEST_TIMEOUT,
            max_retries=DEFAULT_MAX_RETRIES,
        )

        # Internal state and caching
        self._channels_cache: List[StreamingChannel] = []
        self._cache_timestamp: float = 0
        self._file_mtimes: Dict[str, float] = {}  # Track mtime per file
        self._playlist_metadata: Dict = {}

        # Statistics (aggregated across all files)
        self._stats = {
            "total_lines": 0,
            "channels_parsed": 0,
            "channels_skipped": 0,
            "drm_channels": 0,
            "errors": 0,
            "files_parsed": 0,
        }

        # Discover M3U files on initialization
        self._discovered_files = self._discover_m3u_files()
        if self._discovered_files:
            logger.info(
                f"M3U: Discovered {len(self._discovered_files)} playlist file(s): "
                f"{', '.join(self._discovered_files)}"
            )
        else:
            logger.warning(
                f"M3U: No playlist files found in {self.playlists_dir}. "
                f"Provider initialized but get_channels() will return empty list."
            )

    @property
    def provider_name(self) -> str:
        return "m3u"

    @property
    def provider_label(self) -> str:
        return self.PROVIDER_LABEL

    @property
    def provider_logo(self) -> str:
        return self.PROVIDER_LOGO

    @property
    def supported_auth_types(self) -> List[str]:
        return self.SUPPORTED_AUTH_TYPES

    @property
    def uses_dynamic_manifests(self) -> bool:
        return False

    @property
    def implements_epg(self) -> bool:
        return False

    def authenticate(self, **kwargs) -> str:
        """M3U provider doesn't require authentication"""
        logger.debug("M3U: No authentication required")
        return ""

    def refresh_authentication(self) -> str:
        """M3U provider doesn't require authentication"""
        return ""

    # ============================================================================
    # M3U FILE DISCOVERY
    # ============================================================================

    def _discover_m3u_files(self) -> List[str]:
        """
        Discover M3U files in the playlists directory

        Returns:
            List of M3U filenames found
        """
        if self.m3u_filename:
            # Specific file requested
            if self.vfs.exists(self.m3u_filename):
                return [self.m3u_filename]
            else:
                logger.warning(
                    f"M3U: Specified file not found: {self.m3u_filename}"
                )
                return []

        # Auto-discover all *.m3u and *.m3u8 files
        discovered = []
        for ext in ["*.m3u", "*.m3u8"]:
            files = self.vfs.list_files("", pattern=ext)
            discovered.extend(files)

        # Remove duplicates and sort
        discovered = sorted(set(discovered))

        if not discovered:
            logger.debug(
                f"M3U: No playlist files found in {self.playlists_dir} "
                f"(searched for *.m3u and *.m3u8)"
            )

        return discovered

    # ============================================================================
    # M3U PARSING
    # ============================================================================

    def _read_m3u_file(self, filename: str) -> List[str]:
        """
        Read M3U file with encoding fallback support using VFS

        Args:
            filename: M3U filename

        Returns:
            List of lines from the M3U file
        """
        encodings_to_try = [self.encoding] + FALLBACK_ENCODINGS

        for enc in encodings_to_try:
            try:
                content = self.vfs.read_text(filename, encoding=enc)
                if content is None:
                    raise FileNotFoundError(
                        f"M3U file not found: {filename}. "
                        f"Please ensure the file exists in {self.playlists_dir}"
                    )
                lines = content.splitlines()
                logger.debug(
                    f"M3U: Successfully read {filename} with encoding: {enc}"
                )
                return lines
            except UnicodeDecodeError:
                logger.debug(f"M3U: Failed to read {filename} with encoding: {enc}")
                continue
            except FileNotFoundError:
                raise
            except Exception as e:
                logger.error(f"M3U: Error reading {filename}: {e}")
                raise

        raise ValueError(
            f"Could not read M3U file {filename} with any encoding: {encodings_to_try}"
        )

    @staticmethod
    def _parse_attributes(line: str) -> Dict[str, str]:
        """
        Parse attributes from M3U line (TVG attributes, custom attributes)

        Example:
            tvg-id="channel1" tvg-name="Channel One" tvg-logo="logo.png" group-title="News"

        Returns:
            Dictionary of parsed attributes
        """
        attributes = {}

        # Match key="value" or key=value patterns
        pattern = r'([a-zA-Z0-9\-_]+)=["\'](.*?)["\']|([a-zA-Z0-9\-_]+)=(\S+)'
        matches = re.findall(pattern, line)

        for match in matches:
            if match[0] and match[1]:  # Quoted value
                key, value = match[0], match[1]
            elif match[2] and match[3]:  # Unquoted value
                key, value = match[2], match[3]
            else:
                continue

            attributes[key.lower()] = value.strip()

        return attributes

    @staticmethod
    def _extract_extinf_name(line: str) -> str:
        """
        Extract channel name from EXTINF line

        Example:
            #EXTINF:-1 tvg-id="1" tvg-name="Channel",Channel Name
            Returns: "Channel Name"
        """
        # Split on comma - the part after last comma is the name
        parts = line.split(",", 1)
        if len(parts) > 1:
            return parts[1].strip()
        return "Unknown Channel"

    @staticmethod
    def _detect_streaming_format(url: str) -> str:
        """
        Detect streaming format from manifest URL

        Returns:
            Format string: "dash", "hls", "smooth", or default
        """
        url_lower = url.lower()

        for format_type, patterns in MANIFEST_PATTERNS.items():
            if any(pattern in url_lower for pattern in patterns):
                return format_type

        return DEFAULT_STREAMING_FORMAT

    @staticmethod
    def _detect_content_type(name: str, group: Optional[str] = None) -> str:
        """
        Auto-detect content type from channel name and group

        Returns:
            Content type string: "LIVE", "VOD", "RADIO", "SERIES"
        """
        text = f"{name} {group or ''}".lower()

        for content_type, keywords in CONTENT_TYPE_KEYWORDS.items():
            if any(keyword in text for keyword in keywords):
                return content_type

        return DEFAULT_CONTENT_TYPE

    @staticmethod
    def _detect_quality(name: str) -> Optional[str]:
        """
        Detect quality from channel name

        Returns:
            Quality string or None
        """
        name_lower = name.lower()

        for quality, patterns in QUALITY_PATTERNS.items():
            if any(pattern in name_lower for pattern in patterns):
                return quality

        return DEFAULT_QUALITY

    def _parse_drm_config(
            self, attributes: Dict[str, str], properties: Dict[str, str]
    ) -> Optional[DRMConfig]:
        """
        Parse DRM configuration from attributes and properties

        Returns:
            DRMConfig object if DRM detected, None otherwise
        """
        server_url = None
        drm_system_str = None
        clearkey = None
        clearkey_data = {}  # Store full ClearKey JSON data

        # Check DRM attributes
        for attr_key, attr_value in attributes.items():
            if attr_key in DRM_ATTRIBUTES:
                mapped_key = DRM_ATTRIBUTES[attr_key]
                if mapped_key == "license_url":
                    server_url = attr_value
                elif mapped_key == "drm_system":
                    drm_system_str = attr_value.lower()
                elif mapped_key == "clearkey":
                    clearkey = attr_value
                    # Assume it's ClearKey if clearkey attribute is present
                    drm_system_str = "clearkey"

        # Check Kodi/VLC properties
        for prop_key, prop_value in properties.items():
            if "license_key" in prop_key:
                # Check if it's JSON format (either ClearKey format)
                prop_value_stripped = prop_value.strip()
                if prop_value_stripped.startswith("{") and prop_value_stripped.endswith("}"):
                    try:
                        import json
                        license_json = json.loads(prop_value)

                        # Check for ClearKey format 1: {"keys":[{"kty":"oct","kid":"...","k":"..."}]}
                        if "keys" in license_json and isinstance(license_json["keys"], list):
                            if len(license_json["keys"]) > 0:
                                # Extract the key from the first entry
                                first_key = license_json["keys"][0]
                                if isinstance(first_key, dict) and "k" in first_key:
                                    clearkey = first_key["k"]
                                    clearkey_data = license_json

                        # Check for ClearKey format 2: {"kid1":"key1", "kid2":"key2"}
                        elif all(len(k) == 32 for k in license_json.keys()):  # 32 chars = 128 bits in hex
                            # This is likely a ClearKey format with kid:key pairs
                            # Use the first key-value pair
                            for kid, key in license_json.items():
                                clearkey = key
                                clearkey_data = {"keys": [{"k": key, "kid": kid}]}
                                break

                        # If we found a ClearKey, mark as ClearKey system
                        if clearkey:
                            drm_system_str = "clearkey"

                    except (json.JSONDecodeError, AttributeError) as e:
                        logger.debug(f"M3U: Failed to parse license_key as JSON: {e}")
                        # Not JSON, treat as URL/headers format
                        server_url = prop_value.split("|")[0] if "|" in prop_value else prop_value
                else:
                    # Not JSON, treat as URL/headers format
                    server_url = prop_value.split("|")[0] if "|" in prop_value else prop_value

            elif "license_type" in prop_key:
                drm_system_str = prop_value.lower()

        # Create DRM config if we found DRM information
        if server_url or clearkey:
            # Determine DRM system (prioritize license_type if specified)
            if not drm_system_str:
                if clearkey:
                    drm_system_str = "clearkey"
                elif server_url and "clearkey" in server_url.lower():
                    drm_system_str = "clearkey"
                elif server_url and "widevine" in server_url.lower():
                    drm_system_str = "widevine"
                else:
                    drm_system_str = "widevine"  # Default assumption

            # Map to DRMSystem enum
            drm_system_mapping = {
                "widevine": DRMSystem.WIDEVINE,
                "com.widevine.alpha": DRMSystem.WIDEVINE,
                "playready": DRMSystem.PLAYREADY,
                "com.microsoft.playready": DRMSystem.PLAYREADY,
                "clearkey": DRMSystem.CLEARKEY,
                "org.w3.clearkey": DRMSystem.CLEARKEY,
                "fairplay": DRMSystem.FAIRPLAY,
                "com.apple.fps": DRMSystem.FAIRPLAY,
                "wiseplay": DRMSystem.WISEPLAY,
                "com.huawei.wiseplay": DRMSystem.WISEPLAY,
            }

            drm_system = drm_system_mapping.get(
                drm_system_str, DRMSystem.WIDEVINE
            )

            # Create LicenseConfig based on DRM system
            if drm_system == DRMSystem.CLEARKEY:
                license_config = LicenseConfig(
                    clearkey=clearkey,
                    server_url=server_url,
                    additional_data=clearkey_data if clearkey_data else None
                )
            else:
                license_config = LicenseConfig(
                    server_url=server_url,
                )

            return DRMConfig(
                system=drm_system,
                license=license_config,
            )

        return None

    def _parse_channel_entry(
            self,
            extinf_line: str,
            manifest_url: str,
            properties: Dict[str, str],
            channel_number: int,
            source_file: str,
    ) -> Optional[StreamingChannel]:
        """
        Parse a single channel entry from EXTINF line and manifest URL

        Args:
            extinf_line: The #EXTINF line
            manifest_url: The manifest/stream URL
            properties: Accumulated properties (KODIPROP, EXTVLCOPT)
            channel_number: Sequential channel number
            source_file: Source M3U filename

        Returns:
            StreamingChannel object or None if parsing fails
        """
        try:
            # Parse attributes from EXTINF line
            attributes = self._parse_attributes(extinf_line)

            # Extract channel name
            channel_name = self._extract_extinf_name(extinf_line)

            # Build channel data
            channel_data = {
                "name": channel_name,
                "manifest": manifest_url.strip(),
                "provider": self.provider_name,
                "country": self.country,
                "language": DEFAULT_LANGUAGE,
                "description": f"Source: {source_file}",  # Track source file
            }

            # Map TVG attributes
            for tvg_key, mapped_key in TVG_ATTRIBUTES.items():
                if tvg_key in attributes:
                    value = attributes[tvg_key]

                    # Special handling for channel_number
                    if mapped_key == "channel_number":
                        try:
                            value = int(value)
                        except ValueError:
                            logger.warning(f"Invalid channel number: {value}")
                            continue

                    channel_data[mapped_key] = value

            # Map custom attributes
            for custom_key, mapped_key in CUSTOM_ATTRIBUTES.items():
                if custom_key in attributes and mapped_key not in channel_data:
                    channel_data[mapped_key] = attributes[custom_key]

            # Generate channel_id if not present
            if "channel_id" not in channel_data:
                # Use tvg-id if available, otherwise generate from name
                channel_id = attributes.get("tvg-id") or self._generate_channel_id(
                    channel_name, channel_number, source_file
                )
                channel_data["channel_id"] = channel_id

            # Set channel number if not already set
            if "channel_number" not in channel_data:
                channel_data["channel_number"] = channel_number

            # Detect streaming format
            streaming_format = self._detect_streaming_format(manifest_url)
            channel_data["streaming_format"] = streaming_format

            # Detect content type
            content_type = self._detect_content_type(
                channel_name, channel_data.get("genre")
            )
            channel_data["content_type"] = content_type

            # Detect quality
            quality = self._detect_quality(channel_name)
            if quality:
                channel_data["quality"] = quality

            # Parse DRM configuration
            drm_config = self._parse_drm_config(attributes, properties)
            if drm_config:
                channel_data["drm_config"] = drm_config
                channel_data["use_cdm"] = True

            # Apply default configuration
            for key, value in DEFAULT_CHANNEL_CONFIG.items():
                if key not in channel_data:
                    channel_data[key] = value

            # Create StreamingChannel
            channel = StreamingChannel(**channel_data)

            # Auto-detect radio if applicable
            channel.detect_and_set_radio()

            # Validate required fields
            if SKIP_INVALID_CHANNELS:
                for field in REQUIRED_FIELDS:
                    if not getattr(channel, field, None):
                        logger.warning(
                            f"Skipping channel from {source_file} (missing {field}): {channel_name}"
                        )
                        return None

            return channel

        except Exception as e:
            logger.error(f"Error parsing channel entry from {source_file}: {e}")
            self._stats["errors"] += 1
            return None

    @staticmethod
    def _generate_channel_id(name: str, number: int, source_file: str) -> str:
        """
        Generate a unique channel ID from name, number, and source file

        Args:
            name: Channel name
            number: Channel number
            source_file: Source M3U filename

        Returns:
            Channel ID string
        """
        # Clean name: lowercase, remove special chars, replace spaces with underscores
        clean_name = re.sub(r"[^a-z0-9\s]", "", name.lower())
        clean_name = re.sub(r"\s+", "_", clean_name.strip())

        # Clean source file (remove extension and special chars)
        clean_source = re.sub(r"[^a-z0-9]", "_", source_file.lower().rsplit(".", 1)[0])

        return f"{clean_source}_{clean_name}_{number}"

    def _parse_m3u(self, filename: str) -> List[StreamingChannel]:
        """
        Parse a single M3U file and extract all channels

        Args:
            filename: M3U filename to parse

        Returns:
            List of StreamingChannel objects
        """
        logger.info(f"M3U: Parsing file: {filename}")

        lines = self._read_m3u_file(filename)
        file_stats = {
            "total_lines": len(lines),
            "channels_parsed": 0,
            "channels_skipped": 0,
            "drm_channels": 0,
            "errors": 0,
        }

        # Validate M3U header
        if not lines or not lines[0].strip().startswith(M3U_HEADER):
            logger.warning(f"M3U: File {filename} does not start with #EXTM3U header")

        channels = []
        current_extinf = None
        current_properties = {}
        channel_number = 1

        for i, line in enumerate(lines):
            line = line.strip()

            # Replace the skip block with:
            if not line:
                continue
            # Skip ONLY pure comment lines (not directives)
            if line.startswith("#") and not (
                    line.startswith("#EXT") or
                    line.startswith("#KODIPROP:") or  # ← CRITICAL: colon required
                    line.startswith("#EXTVLCOPT:")  # ← CRITICAL: colon required
            ):
                continue

            # Parse EXTINF line
            if line.startswith(EXTINF_PREFIX):
                current_extinf = line
                current_properties = {}  # Reset properties for new channel

            # Parse KODIPROP
            elif line.startswith("#KODIPROP:"):
                prop_line = line[10:].strip()  # Remove #KODIPROP:
                if "=" in prop_line:
                    key, value = prop_line.split("=", 1)
                    current_properties[key.strip().lower()] = value.strip()

            # Parse EXTVLCOPT
            elif line.startswith("#EXTVLCOPT:"):
                prop_line = line[11:].strip()  # Remove #EXTVLCOPT:
                if "=" in prop_line:
                    key, value = prop_line.split("=", 1)
                    current_properties[key.strip().lower()] = value.strip()

            # Parse manifest URL (non-comment line after EXTINF)
            elif current_extinf and not line.startswith("#"):
                manifest_url = line

                # Parse the channel entry
                channel = self._parse_channel_entry(
                    current_extinf,
                    manifest_url,
                    current_properties,
                    channel_number,
                    filename,  # Pass source filename
                )

                if channel:
                    channels.append(channel)
                    channel_number += 1
                    file_stats["channels_parsed"] += 1
                    if channel.drm_config:
                        file_stats["drm_channels"] += 1
                else:
                    file_stats["channels_skipped"] += 1

                # Reset for next channel
                current_extinf = None
                current_properties = {}

        logger.info(
            f"M3U: Parsed {filename}: "
            f"{file_stats['channels_parsed']} channels, "
            f"{file_stats['channels_skipped']} skipped, "
            f"{file_stats['drm_channels']} with DRM, "
            f"{file_stats['errors']} errors"
        )

        # Update aggregate stats
        self._stats["total_lines"] += file_stats["total_lines"]
        self._stats["channels_parsed"] += file_stats["channels_parsed"]
        self._stats["channels_skipped"] += file_stats["channels_skipped"]
        self._stats["drm_channels"] += file_stats["drm_channels"]
        self._stats["errors"] += file_stats["errors"]

        return channels

    # ============================================================================
    # CHANNEL MANAGEMENT
    # ============================================================================

    def _should_refresh_cache(self) -> bool:
        """
        Determine if cache should be refreshed

        Checks:
        - Cache TTL expiration
        - File modification time for any discovered file
        - New files discovered
        """
        current_time = time.time()

        # Check cache TTL
        if current_time - self._cache_timestamp >= self.cache_ttl:
            logger.debug("M3U: Cache TTL expired")
            return True

        # Re-discover files to check for new files
        current_files = self._discover_m3u_files()
        if set(current_files) != set(self._discovered_files):
            logger.debug("M3U: File list changed (new files added or removed)")
            self._discovered_files = current_files
            return True

        # Check if any file has been modified
        for filename in self._discovered_files:
            filepath = self.vfs.join_path(filename)
            # Get file modification time via VFS/filesystem
            try:
                if os.path.isabs(filepath):
                    current_mtime = os.path.getmtime(filepath)
                else:
                    # VFS doesn't have direct mtime, so we read file size as proxy
                    # In production, this could be enhanced
                    current_mtime = time.time()

                previous_mtime = self._file_mtimes.get(filename, 0)
                if current_mtime > previous_mtime:
                    logger.debug(f"M3U: File {filename} has been modified")
                    return True
            except Exception as e:
                logger.warning(f"M3U: Could not check mtime for {filename}: {e}")

        return False

    def get_channels(
            self,
            fetch_manifests: bool = False,
            populate_streaming_data: bool = True,
            force_refresh: bool = False,
            **kwargs,
    ) -> List[StreamingChannel]:
        """
        Get channels from all M3U files with caching support

        Args:
            fetch_manifests: Not used (manifests are in M3U)
            populate_streaming_data: Not used (data is in M3U)
            force_refresh: Force re-parsing of M3U files

        Returns:
            List of StreamingChannel objects from all M3U files
        """
        # Check if refresh needed
        should_refresh = force_refresh or self._should_refresh_cache()

        # Return cached channels if valid
        if not should_refresh and self._channels_cache:
            logger.debug("M3U: Returning channels from cache")
            return self._channels_cache

        logger.info("M3U: Cache expired or force refresh requested. Parsing M3U files...")

        try:
            # Reset aggregate statistics
            self._stats = {
                "total_lines": 0,
                "channels_parsed": 0,
                "channels_skipped": 0,
                "drm_channels": 0,
                "errors": 0,
                "files_parsed": 0,
            }

            # Parse all discovered M3U files
            all_channels = []
            for filename in self._discovered_files:
                try:
                    channels = self._parse_m3u(filename)
                    all_channels.extend(channels)
                    self._stats["files_parsed"] += 1

                    # Update file mtime
                    filepath = self.vfs.join_path(filename)
                    if os.path.isabs(filepath):
                        self._file_mtimes[filename] = os.path.getmtime(filepath)
                    else:
                        self._file_mtimes[filename] = time.time()

                except Exception as e:
                    logger.error(f"M3U: Error parsing {filename}: {e}")
                    self._stats["errors"] += 1

            # Update cache
            self._channels_cache = all_channels
            self._cache_timestamp = time.time()

            logger.info(
                f"M3U: Parsed {self._stats['files_parsed']} file(s), "
                f"loaded {len(all_channels)} total channels"
            )

            return all_channels

        except Exception as e:
            # If parsing fails and we have cached data, return it
            if self._channels_cache:
                logger.error(f"M3U: Failed to parse files: {e}. Serving stale cache.")
                return self._channels_cache
            raise

    def populate_streaming_data(
            self,
            channels: List[StreamingChannel],
            **kwargs,
    ) -> List[StreamingChannel]:
        """
        M3U channels already have streaming data from the file

        Returns:
            Same list of channels
        """
        return channels

    def enrich_channel_data(
            self,
            channel: StreamingChannel,
            **kwargs,
    ) -> Optional[StreamingChannel]:
        """
        M3U channels already have complete data from the file

        Returns:
            Same channel object
        """
        return channel

    def get_manifest(
            self,
            channel_id: str,
            **kwargs,
    ) -> Optional[str]:
        """
        Get manifest URL for a specific channel

        Args:
            channel_id: Channel identifier

        Returns:
            Manifest URL string or None
        """
        channels = self.get_channels()
        for channel in channels:
            if channel.channel_id == channel_id:
                return channel.manifest
        return None

    def get_drm(
            self,
            channel_id: str,
            **kwargs,
    ) -> List[DRMConfig]:
        """
        Get DRM configuration for a specific channel

        Args:
            channel_id: Channel identifier

        Returns:
            List of DRMConfig objects
        """
        channels = self.get_channels()
        for channel in channels:
            if channel.channel_id == channel_id:
                if channel.drm_config:
                    return [channel.drm_config]
        return []

    def get_dynamic_manifest_params(
            self,
            channel: StreamingChannel,
            **kwargs,
    ) -> Optional[str]:
        """
        M3U provider doesn't use dynamic manifests

        Returns:
            None
        """
        return None

    def get_epg(
            self,
            channel_id: str,
            **kwargs,
    ) -> List[Dict]:
        """
        M3U provider doesn't implement EPG

        Returns:
            Empty list
        """
        return []

    # ============================================================================
    # UTILITY METHODS
    # ============================================================================

    def get_statistics(self) -> Dict:
        """
        Get parsing statistics

        Returns:
            Dictionary with parsing stats
        """
        return {
            **self._stats,
            "cache_timestamp": self._cache_timestamp,
            "cached_channels": len(self._channels_cache),
            "discovered_files": self._discovered_files,
            "file_mtimes": self._file_mtimes,
            "playlists_dir": self.playlists_dir,
        }

    def test_connection(self) -> Dict:
        """
        Test M3U files accessibility and parsing

        Returns:
            Test result dictionary
        """
        result = {
            "provider": self.provider_name,
            "playlists_dir": self.playlists_dir,
            "success": False,
            "directory_exists": False,
            "files_discovered": 0,
            "files_readable": 0,
            "channels_parsed": 0,
            "error": None,
        }

        try:
            # Check directory exists
            result["directory_exists"] = self.vfs.exists("")
            if not result["directory_exists"]:
                result["error"] = f"Playlists directory does not exist: {self.playlists_dir}"
                return result

            # Discover files
            files = self._discover_m3u_files()
            result["files_discovered"] = len(files)
            result["discovered_files"] = files

            if not files:
                result["error"] = "No M3U files found in playlists directory"
                return result

            # Try to read each file
            readable_count = 0
            for filename in files:
                try:
                    content = self.vfs.read_text(filename)
                    if content:
                        readable_count += 1
                except Exception as e:
                    logger.warning(f"M3U: Could not read {filename}: {e}")

            result["files_readable"] = readable_count

            if readable_count == 0:
                result["error"] = "No files are readable"
                return result

            # Parse channels
            channels = self.get_channels(force_refresh=True)
            result["channels_parsed"] = len(channels)
            result["statistics"] = self.get_statistics()
            result["success"] = True

        except Exception as e:
            result["error"] = str(e)

        return result

    def close(self) -> None:
        """Close HTTP manager and cleanup resources"""
        if hasattr(self, "http_manager") and self.http_manager:
            self.http_manager.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False