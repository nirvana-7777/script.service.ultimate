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

from ...base.models.drm import DRMConfig, DRMSystem, LicenseConfig
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
            group_filter: Optional[str] = None,
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
            group_filter: Filter to specific group-title (becomes provider name/label)
            proxy_config: Proxy configuration object
            proxy_url: Proxy URL string
            cache_ttl: Cache time-to-live in seconds
            auto_refresh: Auto-refresh playlist when cache expires
            encoding: File encoding (default: utf-8)

        Environment Variables:
            M3U_PLAYLISTS_PATH: Directory containing M3U files (overrides config_dir)
        """
        super().__init__(country=country)

        # Store group filter - this determines provider name/label
        self.group_filter = group_filter

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
            provider_name=self.provider_name,
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
                f"M3U ({self.provider_label}): Discovered {len(self._discovered_files)} playlist file(s): "
                f"{', '.join(self._discovered_files)}"
            )
        else:
            logger.warning(
                f"M3U ({self.provider_label}): No playlist files found in {self.playlists_dir}. "
                f"Provider initialized but get_channels() will return empty list."
            )

    @staticmethod
    def _get_base_provider_name() -> str:
        """Get base provider name (always 'm3u') for internal use"""
        return "m3u"

    @property
    def provider_name(self) -> str:
        """
        Provider name is the cleaned group-title if filtering, otherwise 'm3u'

        This allows each group to be a separate provider instance.
        Examples:
            - "News" -> "news"
            - "Sports & Entertainment" -> "sports_entertainment"
            - "Radio Stations" -> "radio_stations"
        """
        if self.group_filter:
            # Clean group name for provider identifier
            # Remove special characters, lowercase, replace spaces with underscores
            clean_name = re.sub(r'[^a-z0-9\s]+', '', self.group_filter.lower())
            clean_name = re.sub(r'\s+', '_', clean_name).strip('_')
            return clean_name if clean_name else "m3u"
        return "m3u"

    @property
    def provider_label(self) -> str:
        """
        Provider label is the group-title as-is if filtering

        This is what users see in the UI.
        Examples:
            - "News"
            - "Sports & Entertainment"
            - "Radio Stations"
        """
        if self.group_filter:
            return self.group_filter  # Use group title directly
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
            # Use specific file if provided
            if self.vfs.exists(self.m3u_filename):
                return [self.m3u_filename]
            logger.warning(f"M3U: Specified file not found: {self.m3u_filename}")
            return []

        # Auto-discover all M3U files
        discovered = []
        try:
            files = self.vfs.list_files("")
            for file in files:
                if any(file.lower().endswith(ext) for ext in SUPPORTED_EXTENSIONS):
                    discovered.append(file)
        except Exception as e:
            logger.error(f"M3U: Error discovering files: {e}")

        return discovered

    def discover_groups(self) -> List[str]:
        """
        Discover all unique group-titles across all M3U files

        Returns:
            Sorted list of unique group titles
        """
        groups = set()

        for filename in self._discovered_files:
            try:
                lines = self._read_m3u_file(filename)

                for line in lines:
                    if line.startswith(EXTINF_PREFIX):
                        # Extract group-title attributes
                        # Try quoted format first
                        match = re.search(r'group-title="([^"]+)"', line, re.IGNORECASE)
                        if match:
                            groups.add(match.group(1).strip())
                        else:
                            # Try unquoted format
                            match = re.search(r'group-title=([^\s,]+)', line, re.IGNORECASE)
                            if match:
                                groups.add(match.group(1).strip())

            except Exception as e:
                logger.error(f"M3U: Error reading {filename} for group discovery: {e}")

        return sorted(groups)

    # ============================================================================
    # M3U FILE READING & PARSING
    # ============================================================================

    def _read_m3u_file(self, filename: str) -> List[str]:
        """
        Read M3U file with proper encoding handling

        Args:
            filename: M3U filename to read

        Returns:
            List of lines from the file

        Raises:
            ValueError: If file cannot be read with any encoding
        """
        encodings_to_try = [self.encoding] + FALLBACK_ENCODINGS

        for encoding in encodings_to_try:
            try:
                content = self.vfs.read_text(filename, encoding=encoding)
                lines = content.split("\n")
                logger.debug(
                    f"M3U: Successfully read {filename} using {encoding} encoding "
                    f"({len(lines)} lines)"
                )
                return lines
            except (UnicodeDecodeError, UnicodeError):
                logger.debug(f"M3U: Failed to read {filename} with {encoding} encoding")
                continue
            except Exception as e:
                logger.error(f"M3U: Unexpected error reading {filename}: {e}")
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

    @staticmethod
    def _parse_drm_config(
            attributes: Dict[str, str], properties: Dict[str, str]
    ) -> Optional[DRMConfig]:
        """
        Parse DRM configuration from attributes and properties

        Handles:
        - Widevine/PlayReady/FairPlay via license_url
        - ClearKey via JWK format, Kodi shorthand format, AND kid:key format
        - Multi-key ClearKey (video/audio/subtitle tracks)
        - Strict 128-bit hex validation (32 hex chars = 16 bytes)

        Returns:
            DRMConfig object if DRM detected, None otherwise
        """
        keyids: Dict[str, str] = {}  # Unified storage for ALL ClearKey KID:key pairs
        server_url = None
        drm_system_str = None
        raw_license_json = None

        # ============================================================================
        # STEP 1: Extract DRM attributes from EXTINF line attributes
        # ============================================================================
        for attr_key, attr_value in attributes.items():
            if attr_key in DRM_ATTRIBUTES:
                mapped_key = DRM_ATTRIBUTES[attr_key]
                if mapped_key == "license_url":
                    server_url = attr_value.strip() if attr_value else None
                elif mapped_key == "drm_system":
                    drm_system_str = attr_value.lower().strip() if attr_value else None

        # ============================================================================
        # STEP 2: Extract DRM properties from KODIPROP/EXTVLCOPT
        # ============================================================================
        # Check license_type first (determines DRM system)
        license_type_prop = (
                properties.get("inputstream.adaptive.license_type") or
                properties.get("inputstream.adaptive.licensetype")
        )
        if license_type_prop:
            drm_system_str = license_type_prop.lower().strip()

        # Check license_key (contains ClearKey JSON, kid:key format, or license server URL)
        license_key_prop = (
                properties.get("inputstream.adaptive.license_key") or
                properties.get("inputstream.adaptive.licensekey")
        )
        if license_key_prop:
            license_key_prop = license_key_prop.strip()

            # ========================================================================
            # NEW: Handle kid:key format (colon-separated 128-bit hex)
            # Example: d3c6cfa92bee2619a805911a14fe3827:d724545e509457efa94c57689eb68d4a
            # ========================================================================
            if ":" in license_key_prop and not (
                    license_key_prop.startswith("{") or
                    license_key_prop.startswith("http") or
                    "|" in license_key_prop
            ):
                parts = license_key_prop.split(":", 1)
                if len(parts) == 2:
                    kid_hex = parts[0].strip().lower()
                    key_hex = parts[1].strip().lower()

                    # Validate 128-bit hex format (32 hex chars = 16 bytes)
                    valid_hex = set("0123456789abcdef")
                    if (
                            len(kid_hex) == 32 and all(c in valid_hex for c in kid_hex) and
                            len(key_hex) == 32 and all(c in valid_hex for c in key_hex)
                    ):
                        keyids[kid_hex] = key_hex
                        drm_system_str = "clearkey"
                        logger.debug(f"Parsed kid:key ClearKey format: KID={kid_hex}, KEY=*** (128-bit)")
                    else:
                        logger.warning(
                            f"Invalid kid:key format: KID='{kid_hex}' ({len(kid_hex)} chars), "
                            f"KEY='{key_hex}' ({len(key_hex)} chars) - skipping"
                        )

            # Handle pipe-delimited format: URL|headers|post_data|response_data
            elif "|" in license_key_prop and not (
                    license_key_prop.startswith("{") and license_key_prop.endswith("}")
            ):
                parts = license_key_prop.split("|", 3)
                server_url = parts[0].strip() if parts[0].strip() else None

            # Handle JSON format (ClearKey only)
            elif license_key_prop.startswith("{") and license_key_prop.endswith("}"):
                try:
                    import json, base64
                    raw_license_json = json.loads(license_key_prop)

                    # FORMAT 1: JWK format {"keys": [{"kid": "base64_kid", "k": "base64_key"}, ...]}
                    if "keys" in raw_license_json and isinstance(raw_license_json["keys"], list):
                        for entry in raw_license_json["keys"]:
                            if not (isinstance(entry, dict) and "kid" in entry and "k" in entry):
                                continue

                            try:
                                # Decode base64 KID → 128-bit hex (32 chars)
                                kid_b64 = entry["kid"].replace("-", "+").replace("_", "/")
                                kid_b64 += "=" * (-len(kid_b64) % 4)  # Pad for base64
                                kid_bytes = base64.b64decode(kid_b64)
                                if len(kid_bytes) != 16:
                                    logger.warning(f"Invalid KID length: {len(kid_bytes)} bytes (expected 16)")
                                    continue
                                kid_hex = kid_bytes.hex().lower()

                                # Decode base64 key → 128-bit hex (32 chars)
                                key_b64 = entry["k"].replace("-", "+").replace("_", "/")
                                key_b64 += "=" * (-len(key_b64) % 4)
                                key_bytes = base64.b64decode(key_b64)
                                if len(key_bytes) != 16:
                                    logger.warning(f"Invalid KEY length: {len(key_bytes)} bytes (expected 16)")
                                    continue
                                key_hex = key_bytes.hex().lower()

                                keyids[kid_hex] = key_hex
                                logger.debug(f"Parsed JWK ClearKey: KID={kid_hex}, KEY=*** (128-bit)")

                            except Exception as e:
                                logger.warning(f"Failed to decode JWK entry: {e}")
                                continue

                    # FORMAT 2: Kodi shorthand {"kid_hex": "key_hex", ...} (raw 128-bit hex)
                    elif isinstance(raw_license_json, dict):
                        valid_hex = set("0123456789abcdefABCDEF")
                        for kid, key in raw_license_json.items():
                            # Validate 128-bit hex format (32 hex chars = 16 bytes)
                            if (
                                    isinstance(kid, str) and len(kid) == 32 and
                                    all(c in valid_hex for c in kid) and
                                    isinstance(key, str) and len(key) == 32 and
                                    all(c in valid_hex for c in key)
                            ):
                                keyids[kid.lower()] = key.lower()
                                logger.debug(f"Parsed Kodi ClearKey: KID={kid.lower()}, KEY=*** (128-bit)")
                            else:
                                logger.warning(
                                    f"Invalid ClearKey hex format: KID='{kid}' ({len(kid)} chars), "
                                    f"KEY='{key}' ({len(key)} chars) - skipping"
                                )

                    # Special case: single key without "keys" wrapper (rare)
                    elif "kid" in raw_license_json and "k" in raw_license_json:
                        try:
                            kid_b64 = raw_license_json["kid"].replace("-", "+").replace("_", "/")
                            kid_b64 += "=" * (-len(kid_b64) % 4)
                            kid_bytes = base64.b64decode(kid_b64)
                            if len(kid_bytes) == 16:
                                kid_hex = kid_bytes.hex().lower()

                                key_b64 = raw_license_json["k"].replace("-", "+").replace("_", "/")
                                key_b64 += "=" * (-len(key_b64) % 4)
                                key_bytes = base64.b64decode(key_b64)
                                if len(key_bytes) == 16:
                                    key_hex = key_bytes.hex().lower()
                                    keyids[kid_hex] = key_hex
                                    logger.debug(f"Parsed single-key ClearKey: KID={kid_hex}, KEY=***")
                        except Exception as e:
                            logger.warning(f"Failed to decode single-key JWK: {e}")

                except json.JSONDecodeError as e:
                    logger.debug(f"Invalid JSON in license_key (treating as URL): {e}")
                    # Fallback: treat entire value as license server URL
                    server_url = license_key_prop.split("|")[0].strip() if "|" in license_key_prop else license_key_prop

        # ============================================================================
        # STEP 3: Determine DRM system using centralized mapping
        # ============================================================================
        # Auto-detect if not explicitly set
        if not drm_system_str:
            if keyids:  # ClearKey detected via keyids
                drm_system_str = "clearkey"
            elif server_url:
                url_lower = server_url.lower()
                if "clearkey" in url_lower:
                    drm_system_str = "clearkey"
                elif "widevine" in url_lower:
                    drm_system_str = "widevine"
                elif "playready" in url_lower:
                    drm_system_str = "playready"
                elif "fairplay" in url_lower or "skd://" in url_lower:
                    drm_system_str = "fairplay"
                else:
                    drm_system_str = "widevine"  # Default assumption

        # Resolve alias → enum using centralized mapping
        drm_system = DRMSystem.from_alias(drm_system_str) or DRMSystem.WIDEVINE

        # ============================================================================
        # STEP 4: Create LicenseConfig with proper fields (NO 'clearkey' field!)
        # ============================================================================
        license_config = None

        if drm_system == DRMSystem.CLEARKEY and keyids:
            # Strict 128-bit hex validation before creating config
            valid_keyids = {}
            for kid, key in keyids.items():
                if len(kid) != 32 or not all(c in "0123456789abcdef" for c in kid):
                    logger.warning(f"Invalid KID format (not 128-bit hex): {kid}")
                    continue
                if len(key) != 32 or not all(c in "0123456789abcdef" for c in key):
                    logger.warning(f"Invalid KEY format (not 128-bit hex): {key}")
                    continue
                valid_keyids[kid] = key

            if not valid_keyids:
                logger.warning("ClearKey DRM detected but no valid 128-bit hex keys found")
                return None

            license_config = LicenseConfig(
                server_url=server_url,  # Optional fallback license server
                keyids=valid_keyids,  # ← CORRECT FIELD (Dict[str, str] of 128-bit hex pairs)
            )
        else:
            # Non-ClearKey DRM or ClearKey without keys (license server only)
            license_config = LicenseConfig(
                server_url=server_url,
            )

        # ============================================================================
        # STEP 5: Final validation and return
        # ============================================================================
        if not server_url and not (drm_system == DRMSystem.CLEARKEY and keyids):
            # No usable DRM configuration
            return None

        try:
            # Validate before returning (will raise on invalid hex formats)
            if license_config:
                license_config.validate()
        except ValueError as e:
            logger.warning(f"Invalid DRM configuration: {e}")
            return None

        return DRMConfig(
            system=drm_system,
            license=license_config,
        )

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
            manifest_url: The manifest/stream URL (may contain | separated headers)
            properties: Accumulated properties (KODIPROP, EXTVLCOPT)
            channel_number: Sequential channel number
            source_file: Source M3U filename

        Returns:
            StreamingChannel object or None if parsing fails
        """
        try:
            # ============================================================================
            # STEP 1: Parse URL and extract headers if present (pipe-delimited format)
            # ============================================================================
            # Split on pipe to separate URL from headers
            manifest_parts = manifest_url.strip().split("|", 1)
            clean_url = manifest_parts[0].strip()
            url_headers_raw = manifest_parts[1].strip() if len(manifest_parts) > 1 else None

            # Parse attributes from EXTINF line
            attributes = self._parse_attributes(extinf_line)

            # Extract channel name
            channel_name = self._extract_extinf_name(extinf_line)

            # Build channel data
            channel_data = {
                "name": channel_name,
                "manifest": clean_url,  # Store clean URL without headers
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

            # ========================================================================
            # IMPROVEMENT 1: Enhanced channel_id fallback chain
            # tvg-id → tvg-name → generated_id
            # ========================================================================
            if "channel_id" not in channel_data:
                # Fallback chain: tvg-id → tvg-name → generated_id
                channel_id = (
                        attributes.get("tvg-id") or
                        attributes.get("tvg-name") or
                        self._generate_channel_id(channel_name, channel_number, source_file)
                )
                channel_data["channel_id"] = channel_id

            # Set channel number if not already set
            if "channel_number" not in channel_data:
                channel_data["channel_number"] = channel_number

            # ========================================================================
            # IMPROVEMENT 2: Fallback group-title to M3U filename
            # If no genre/group-title found, use the M3U filename as genre
            # ========================================================================
            if "genre" not in channel_data:
                # Extract filename without extension and format nicely
                fallback_genre = source_file.rsplit(".", 1)[0].replace("_", " ").replace("-", " ").title()
                channel_data["genre"] = fallback_genre
                logger.debug(f"No group-title found, using M3U filename as genre: {fallback_genre}")

            # Detect streaming format
            streaming_format = self._detect_streaming_format(clean_url)
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

            # ============================================================================
            # STEP 2: Parse DRM configuration
            # ============================================================================
            drm_config = self._parse_drm_config(attributes, properties)

            # If URL has headers, add them to the DRM configuration
            if drm_config and drm_config.license and url_headers_raw:
                # Parse headers from format: header1="value1" header2="value2"
                # Convert to standard format: header1: value1&header2: value2
                header_lines = []

                # Use regex to find all header="value" pairs
                header_matches = re.findall(r'(\S+?)="([^"]*)"', url_headers_raw)

                for header_name, header_value in header_matches:
                    header_lines.append(f"{header_name}: {header_value}")

                # Also handle any headers without quotes (unlikely but possible)
                remaining = url_headers_raw
                for match in header_matches:
                    remaining = remaining.replace(f'{match[0]}="{match[1]}"', '')

                # Split remaining by space and look for key=value pairs
                for part in remaining.split():
                    if part and '=' in part:
                        key, value = part.split('=', 1)
                        header_lines.append(f"{key}: {value}")

                if header_lines:
                    headers_str = "&".join(header_lines)
                    if drm_config.license.req_headers:
                        # Merge with existing headers
                        drm_config.license.req_headers += "&" + headers_str
                    else:
                        drm_config.license.req_headers = headers_str

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

    def get_channels(
            self,
            force_refresh: bool = False,
            **kwargs,
    ) -> List[StreamingChannel]:
        """
        Get all channels from M3U files

        Args:
            force_refresh: Force re-parsing of M3U files

        Returns:
            List of StreamingChannel objects
        """
        try:
            # Check if cache is still valid
            cache_valid = False
            if not force_refresh and self._channels_cache:
                cache_age = time.time() - self._cache_timestamp
                cache_valid = cache_age < self.cache_ttl

                # Also check if any files have been modified
                if cache_valid:
                    for filename in self._discovered_files:
                        filepath = self.vfs.join_path(filename)
                        if os.path.isabs(filepath):
                            current_mtime = os.path.getmtime(filepath)
                            if filename not in self._file_mtimes or self._file_mtimes[filename] < current_mtime:
                                cache_valid = False
                                logger.info(f"M3U: File {filename} has been modified, refreshing cache")
                                break

            # Return cached channels if valid
            if cache_valid:
                logger.debug(
                    f"M3U ({self.provider_label}): Returning {len(self._channels_cache)} cached channels"
                )
                return self._channels_cache

            # Re-discover files if auto_refresh is enabled
            if self.auto_refresh:
                self._discovered_files = self._discover_m3u_files()

            # Reset stats for fresh parsing
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
                    logger.error(f"M3U ({self.provider_label}): Error parsing {filename}: {e}")
                    self._stats["errors"] += 1

            # Filter by group if group_filter is set
            if self.group_filter:
                filtered_channels = [
                    ch for ch in all_channels
                    if ch.genre and ch.genre.strip().lower() == self.group_filter.strip().lower()
                ]
                logger.info(
                    f"M3U ({self.provider_label}): Filtered {len(all_channels)} channels to "
                    f"{len(filtered_channels)} matching group '{self.group_filter}'"
                )
                all_channels = filtered_channels

            # Update cache
            self._channels_cache = all_channels
            self._cache_timestamp = time.time()

            logger.info(
                f"M3U ({self.provider_label}): Parsed {self._stats['files_parsed']} file(s), "
                f"loaded {len(all_channels)} total channels"
            )

            return all_channels

        except Exception as e:
            # If parsing fails and we have cached data, return it
            if self._channels_cache:
                logger.error(f"M3U ({self.provider_label}): Failed to parse files: {e}. Serving stale cache.")
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
                if channel.drm_config is not None:
                    # Return as a list for consistency
                    return [channel.drm_config]
                break  # Found channel but no DRM config

        # Return empty list if no config found
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