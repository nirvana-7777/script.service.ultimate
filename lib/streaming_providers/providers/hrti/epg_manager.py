# streaming_providers/providers/hrti/epg_manager.py
"""
HRTi EPG Manager - Handles Electronic Program Guide operations.
"""

import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple

from ...base.models.epg_models import EPGEntry
from ...base.utils.logger import logger


class HRTiEPGManager:
    """Manages HRTi EPG operations."""

    # Default EPG window: 2 days past, 7 days future
    DEFAULT_PAST_DAYS = 2
    DEFAULT_FUTURE_DAYS = 7

    def __init__(self, provider):
        self.provider = provider
        self._config = provider.hrti_config
        self._http_manager = provider.http_manager
        self._authenticator = provider.authenticator
        self._channels_cache = None

    def _get_headers(self, referer_path: str = "/tv") -> Dict[str, str]:
        """Build authenticated headers for EPG API calls."""
        headers = {
            "deviceid": self._authenticator.get_device_id(),
            "devicetypeid": self._config.device_reference_id,
            "ipaddress": self._authenticator.get_ip_address(),
            "operatorreferenceid": self._config.operator_reference_id,
            "origin": self._config.base_website,
            "referer": f"{self._config.base_website}{referer_path}",
            "User-Agent": self._config.user_agent,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        token = (
            self._authenticator._current_token.access_token
            if self._authenticator._current_token
            else ""
        )
        if token:
            headers["authorization"] = f"Client {token}"
        return headers

    def get_epg_for_channel(
            self,
            channel_id: str,
            start_time: Optional[datetime] = None,
            end_time: Optional[datetime] = None,
    ) -> List[EPGEntry]:
        """
        Get EPG data for a single channel.

        Args:
            channel_id: Channel reference ID (e.g., "40013")
            start_time: Start time for EPG query (default: now - DEFAULT_PAST_DAYS days)
            end_time: End time for EPG query (default: now + DEFAULT_FUTURE_DAYS days)

        Returns:
            List of EPGEntry objects
        """
        # Set default time range if not provided
        now = datetime.now()
        if start_time is None:
            start_time = now - timedelta(days=self.DEFAULT_PAST_DAYS)
        if end_time is None:
            end_time = now + timedelta(days=self.DEFAULT_FUTURE_DAYS)

        # Convert to milliseconds timestamp for API
        start_ts = int(start_time.timestamp() * 1000)
        end_ts = int(end_time.timestamp() * 1000)

        try:
            headers = self._get_headers()
            payload = {
                "ChannelReferenceIds": [channel_id],
                "StartTime": f"/Date({start_ts})/",
                "EndTime": f"/Date({end_ts})/",
            }

            logger.debug(f"Fetching EPG for channel {channel_id}: {start_time} to {end_time}")

            response = self._http_manager.post(
                self._config.api_endpoints["programme"],
                operation="api",
                headers=headers,
                data=json.dumps(payload),
            )
            response.raise_for_status()

            data = response.json()
            if data.get("ErrorCode", 0) != 0:
                logger.warning(f"EPG API error: {data.get('ErrorDescription')}")
                return []

            result = data.get("Result", [])
            if not result:
                return []

            # Find the channel in the result
            channel_data = None
            for item in result:
                if item.get("ReferenceID") == channel_id:
                    channel_data = item
                    break

            if not channel_data:
                logger.debug(f"No EPG data found for channel {channel_id}")
                return []

            epg_list = channel_data.get("EpgList", [])

            # Convert to EPGEntry objects
            entries = []
            for epg_item in epg_list:
                entry = self._parse_epg_item(epg_item, channel_id)
                if entry:
                    entries.append(entry)

            logger.debug(f"Retrieved {len(entries)} EPG entries for channel {channel_id}")
            return entries

        except Exception as e:
            logger.error(f"Error fetching EPG for channel {channel_id}: {e}")
            return []

    def get_epg_for_all_channels(
            self,
            start_time: Optional[datetime] = None,
            end_time: Optional[datetime] = None,
    ) -> Dict[str, List[EPGEntry]]:
        """
        Get EPG data for all channels in a single API call.

        Note: HRTi API supports fetching EPG for all channels at once,
        which is more efficient than per-channel calls.

        Returns:
            Dictionary mapping channel_id -> list of EPGEntry objects
        """
        # Set default time range
        now = datetime.now()
        if start_time is None:
            start_time = now - timedelta(days=self.DEFAULT_PAST_DAYS)
        if end_time is None:
            end_time = now + timedelta(days=self.DEFAULT_FUTURE_DAYS)

        start_ts = int(start_time.timestamp() * 1000)
        end_ts = int(end_time.timestamp() * 1000)

        # Get all channel IDs from provider
        channels = self._get_all_channels()
        if not channels:
            return {}

        channel_ids = [ch.content_id for ch in channels]

        try:
            headers = self._get_headers()
            payload = {
                "ChannelReferenceIds": channel_ids,
                "StartTime": f"/Date({start_ts})/",
                "EndTime": f"/Date({end_ts})/",
            }

            logger.debug(f"Fetching EPG for {len(channel_ids)} channels")

            response = self._http_manager.post(
                self._config.api_endpoints["programme"],
                operation="api",
                headers=headers,
                data=json.dumps(payload),
            )
            response.raise_for_status()

            data = response.json()
            if data.get("ErrorCode", 0) != 0:
                logger.warning(f"EPG API error: {data.get('ErrorDescription')}")
                return {}

            result = data.get("Result", [])

            # Parse results per channel
            epg_by_channel = {}
            for channel_data in result:
                channel_id = channel_data.get("ReferenceID")
                if not channel_id:
                    continue

                epg_list = channel_data.get("EpgList", [])
                entries = []
                for epg_item in epg_list:
                    entry = self._parse_epg_item(epg_item, channel_id)
                    if entry:
                        entries.append(entry)

                if entries:
                    epg_by_channel[channel_id] = entries

            logger.debug(f"Retrieved EPG for {len(epg_by_channel)} channels")
            return epg_by_channel

        except Exception as e:
            logger.error(f"Error fetching EPG for all channels: {e}")
            return {}

    def get_epg_details(self, reference_id: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information for a specific EPG entry.

        This is useful for catch-up functionality as it provides the
        FileName (streaming URL) for the recorded program.

        Args:
            reference_id: EPG entry reference ID

        Returns:
            Dictionary with EPG details including FileName
        """
        try:
            headers = self._get_headers("/tv")
            payload = {
                "ChannelReferenceId": "",  # Not required, but API expects it
                "ReferenceId": reference_id,
            }

            response = self._http_manager.post(
                self._config.api_endpoints["epg_details"],
                operation="api",
                headers=headers,
                data=json.dumps(payload),
            )
            response.raise_for_status()

            data = response.json()
            if data.get("ErrorCode", 0) != 0:
                logger.warning(f"EPG details API error: {data.get('ErrorDescription')}")
                return None

            return data.get("Result")

        except Exception as e:
            logger.error(f"Error fetching EPG details for {reference_id}: {e}")
            return None

    def _parse_epg_item(self, item: Dict[str, Any], channel_id: str) -> Optional[EPGEntry]:
        """
        Parse a single EPG item from API response into EPGEntry.

        Expected item format from GetProgramme:
        {
            "AdultContent": false,
            "CategoryReferenceId": "VIJESTI",
            "ContentRating": "",
            "ImagePath": "https://...",
            "ReferenceID": "2059396656",
            "TimeEnd": "/Date(1777725000000)/",
            "TimeEndUnixEpoch": 1777725000,
            "TimeStart": "/Date(1777723200000)/",
            "TimeStartUnixEpoch": 1777723200,
            "Title": "Vijesti"
        }
        """
        try:
            # Extract timestamps (prefer Unix epoch, fallback to parsing /Date() format)
            start = item.get("TimeStartUnixEpoch")
            if start is None:
                start_str = item.get("TimeStart", "")
                start = self._parse_date_string(start_str)

            end = item.get("TimeEndUnixEpoch")
            if end is None:
                end_str = item.get("TimeEnd", "")
                end = self._parse_date_string(end_str)

            if not start or not end:
                logger.warning(f"Missing timestamps for EPG item: {item.get('ReferenceID')}")
                return None

            title = item.get("Title", "").strip()
            if not title:
                return None

            # Generate broadcast ID (32-bit unique identifier)
            broadcast_id = EPGEntry.encode_broadcast_id(
                self.provider.provider_name,
                channel_id,
                start
            )

            # Get genre type from CategoryReferenceId
            genre_type = self._map_category_to_genre(item.get("CategoryReferenceId", ""))

            return EPGEntry(
                broadcast_id=broadcast_id,
                title=title,
                start=start,
                end=end,
                description=item.get("DescriptionShort") or item.get("DescriptionLong"),
                icon=item.get("ImagePath"),
                genre=genre_type,
                genre_description=item.get("CategoryReferenceId"),
                parental_rating=self._parse_parental_rating(item.get("ContentRating")),
                flags=EPGFlags.IS_SERIES if item.get("IsSeries", False) else EPGFlags.UNDEFINED,
            )

        except Exception as e:
            logger.error(f"Error parsing EPG item: {e}")
            return None

    @staticmethod
    def _parse_date_string(date_str: str) -> Optional[int]:
        """Parse /Date(timestamp)/ format to Unix timestamp."""
        if not date_str:
            return None

        import re
        match = re.search(r'/Date\((\d+)\)/', date_str)
        if match:
            # Convert milliseconds to seconds
            return int(match.group(1)) // 1000

        return None

    @staticmethod
    def _map_category_to_genre(category: str) -> int:
        """
        Map HRTi category to EPG genre type.
        Based on ETSI EN 300 468 DVB-SI standard.
        """
        category_map = {
            "VIJESTI": EPGGenre.NEWSCURRENTAFFAIRS,  # News/Current Affairs
            "SPORT": EPGGenre.SPORTS,  # Sports
            "GLAZBA": EPGGenre.MUSICBALLETDANCE,  # Music/Ballet/Dance
            "IGRANI PROGRAM": EPGGenre.MOVIEDRAMA,  # Movie/Drama
            "UMJETNOST I KULTURA": EPGGenre.ARTSCULTURE,  # Arts/Culture
            "ZABAVA": EPGGenre.SHOW,  # Show/Game Show
            "RELIGIJA": EPGGenre.SOCIALPOLITICALECONOMICS,  # Religion
            "OBRAZOVANJE": EPGGenre.EDUCATIONALSCIENCE,  # Educational
            "ZNANOST": EPGGenre.EDUCATIONALSCIENCE,  # Science
            "DRUGI INFORMATIVNI SADRŽAJI": EPGGenre.NEWSCURRENTAFFAIRS,
            "PROMOCIJA": EPGGenre.SHOW,
            "KOMERCIJALNI PROGRAMI": EPGGenre.SHOW,
        }

        return category_map.get(category, EPGGenre.UNDEFINED)

    @staticmethod
    def _parse_parental_rating(rating_str: str) -> Optional[int]:
        """Parse parental rating string to integer."""
        if not rating_str:
            return None

        # Try to extract number from strings like "12", "FSK 12", "12+"
        import re
        match = re.search(r'(\d+)', rating_str)
        if match:
            return int(match.group(1))

        return None

    def _get_all_channels(self):
        """Get all channels from provider (with caching)."""
        if self._channels_cache is None:
            self._channels_cache = self.provider.get_channels()
        return self._channels_cache

    def get_epg_window(self) -> Tuple[int, int]:
        """
        Return the EPG window as (past_days, future_days).

        Returns:
            Tuple of (past_days, future_days)
        """
        return self.DEFAULT_PAST_DAYS, self.DEFAULT_FUTURE_DAYS


# Import EPG models at the bottom to avoid circular imports
from ...base.models.epg_models import EPGEntry, EPGGenre, EPGFlags