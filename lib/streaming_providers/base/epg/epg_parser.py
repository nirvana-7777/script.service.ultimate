#!/usr/bin/env python3
# streaming_providers/base/epg/epg_parser.py
"""
XMLTV EPG Parser for Kodi PVR Backend
Parses XMLTV format and converts to Kodi PVR EPG format
"""

import gzip
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from ..models import epg_models
from ..models.epg_models import EPGEntry
from ..utils.logger import logger

# Import constants with proper naming
EPGGenre = epg_models.EPGGenre
EPGFlags = epg_models.EPGFlags


class EPGParser:
    """
    Parses XMLTV EPG data and converts to Kodi PVR format.
    Uses streaming parse for performance with large EPG files.

    Now returns EPGEntry objects internally for validation and type safety.
    """

    def __init__(self):
        """Initialize parser with provider registry for broadcast ID encoding."""
        # Provider registry maps provider hash -> provider name
        # Used to look up provider from broadcast_id during catchup
        self._provider_registry: Dict[int, str] = {}

    def register_provider(self, provider_name: str) -> int:
        """
        Register a provider and return its hash.
        This enables provider lookup from broadcast IDs.

        Args:
            provider_name: Provider name to register

        Returns:
            Provider hash (16-bit)
        """
        import hashlib

        provider_hash_obj = hashlib.sha256(provider_name.encode("utf-8"))
        provider_hash = int(provider_hash_obj.hexdigest()[:4], 16)

        self._provider_registry[provider_hash] = provider_name
        logger.debug(f"Registered provider '{provider_name}' with hash {provider_hash:04x}")

        return provider_hash

    def get_provider_from_broadcast_id(self, broadcast_id: int) -> Optional[str]:
        """
        Get provider name from broadcast ID.
        Useful for catchup operations where only broadcast_id is available.

        Args:
            broadcast_id: Encoded broadcast ID

        Returns:
            Provider name, or None if not found in registry
        """
        provider_hash = EPGEntry.get_provider_hash(broadcast_id)
        provider_name = self._provider_registry.get(provider_hash)

        if not provider_name:
            logger.warning(
                f"Provider not found for broadcast_id {broadcast_id} "
                f"(hash: {provider_hash:04x})"
            )

        return provider_name

    @staticmethod
    def parse_xmltv_time(time_str: str) -> Optional[int]:
        """
        Parse XMLTV time format to Unix timestamp.
        Format: yyyyMMddHHmmss +HHMM
        Example: 20240101200000 +0100

        Args:
            time_str: XMLTV formatted time string

        Returns:
            Unix timestamp or None if parsing fails
        """
        if not time_str:
            return None

        try:
            # Split timestamp and timezone
            parts = time_str.strip().split()
            if not parts:
                return None

            dt_str = parts[0]

            # Parse basic timestamp
            dt = datetime.strptime(dt_str, "%Y%m%d%H%M%S")

            # Handle timezone offset if present
            if len(parts) > 1:
                tz_str = parts[1]
                if tz_str.startswith(("+", "-")):
                    sign = 1 if tz_str[0] == "+" else -1
                    hours = int(tz_str[1:3])
                    minutes = int(tz_str[3:5]) if len(tz_str) > 3 else 0
                    # Adjust for timezone (subtract offset to get UTC)
                    from datetime import timedelta

                    dt = dt - timedelta(hours=sign * hours, minutes=sign * minutes)

            return int(dt.timestamp())

        except (ValueError, IndexError) as e:
            logger.warning(f"Failed to parse XMLTV time '{time_str}': {e}")
            return None

    @staticmethod
    def generate_broadcast_id(
        channel_id: str, start_time: int, provider_name: Optional[str] = None
    ) -> int:
        """
        Generate deterministic broadcast ID from channel and start time.

        If provider_name is given, uses encode_broadcast_id() for provider-aware IDs.
        Otherwise, falls back to legacy hash-only method.

        Args:
            channel_id: EPG channel ID
            start_time: Unix timestamp of programme start
            provider_name: Optional provider name for encoding

        Returns:
            Unique integer broadcast ID
        """
        if provider_name:
            # New method: encode provider information
            return EPGEntry.encode_broadcast_id(provider_name, channel_id, start_time)
        else:
            # Legacy method: simple hash (for backward compatibility)
            import hashlib

            hash_input = f"{channel_id}_{start_time}".encode("utf-8")
            hash_digest = hashlib.sha256(hash_input).hexdigest()
            # Convert first 8 hex chars to int (32-bit)
            return int(hash_digest[:8], 16)

    @staticmethod
    def parse_episode_num(
        episode_elem: ET.Element,
    ) -> Tuple[Optional[int], Optional[int], Optional[int]]:
        """
        Parse episode numbering from XMLTV episode-num element.

        Supports two systems:
        - xmltv_ns: "season.episode.part/total" (0-indexed, e.g., "4.11.0/1" = S05E12)
        - onscreen: "S05E12" format

        Args:
            episode_elem: episode-num XML element

        Returns:
            Tuple of (series_number, episode_number, episode_part_number)
        """
        system = episode_elem.get("system", "")
        text = episode_elem.text or ""

        if system == "xmltv_ns":
            # Format: "season.episode.part/total" but may have spaces like "11 . 6 . "
            # Clean up spaces around dots
            text = text.strip()
            # Replace spaces around dots and remove multiple spaces
            import re

            text = re.sub(r"\s*\.\s*", ".", text)

            try:
                # Remove trailing slash if present without numerator (e.g., "0.5.")
                if text.endswith("."):
                    text = text[:-1]

                parts = text.split(".")
                if len(parts) >= 2:
                    # Handle season number
                    season_str = parts[0].split("/")[0] if parts[0] else None
                    series_num = int(season_str) + 1 if season_str and season_str.strip() else None

                    # Handle episode number
                    episode_str = parts[1].split("/")[0] if len(parts) > 1 and parts[1] else None
                    episode_num = (
                        int(episode_str) + 1 if episode_str and episode_str.strip() else None
                    )

                    # Handle part number (optional)
                    part_num = None
                    if len(parts) >= 3 and parts[2]:
                        part_str = parts[2].split("/")[0]
                        part_num = int(part_str) + 1 if part_str and part_str.strip() else None

                    return series_num, episode_num, part_num
            except (ValueError, IndexError) as e:
                logger.debug(f"Failed to parse xmltv_ns episode number '{episode_elem.text}': {e}")

        elif system == "onscreen":
            # Format: "S05E12" or "5x12"
            try:
                import re

                # Try S##E## format
                match = re.match(r"S(\d+)E(\d+)", text, re.IGNORECASE)
                if match:
                    return int(match.group(1)), int(match.group(2)), None
                # Try #x## format
                match = re.match(r"(\d+)x(\d+)", text)
                if match:
                    return int(match.group(1)), int(match.group(2)), None
            except (ValueError, AttributeError) as e:
                logger.debug(f"Failed to parse onscreen episode number '{text}': {e}")

        return None, None, None

    @staticmethod
    def parse_star_rating(rating_elem: ET.Element) -> Optional[int]:
        """
        Parse star rating from XMLTV format to 0-10 scale.

        Args:
            rating_elem: star-rating XML element

        Returns:
            Rating as integer 0-10, or None
        """
        value_elem = rating_elem.find("value")
        if value_elem is not None and value_elem.text:
            try:
                # Format can be "8/10" or "4/5" or just "8"
                text = value_elem.text.strip()
                if "/" in text:
                    parts = text.split("/")
                    numerator = float(parts[0])
                    denominator = float(parts[1])
                    # Normalize to 0-10 scale
                    rating = int((numerator / denominator) * 10)
                    return min(10, max(0, rating))
                else:
                    # Assume already 0-10 scale
                    rating = int(float(text))
                    return min(10, max(0, rating))
            except (ValueError, IndexError) as e:
                logger.debug(f"Failed to parse star rating '{value_elem.text}': {e}")
        return None

    @staticmethod
    def _map_genre_to_type(genre_str: str) -> int:
        """
        Map genre string to numeric genre type based on DVB-SI standard.

        Args:
            genre_str: Genre string from XMLTV (lowercase)

        Returns:
            Numeric genre type from EPGGenre (DVB-SI ETSI EN 300 468)
        """
        if "movie" in genre_str or "film" in genre_str or "drama" in genre_str:
            return EPGGenre.MOVIEDRAMA
        elif "news" in genre_str:
            return EPGGenre.NEWSCURRENTAFFAIRS
        elif "show" in genre_str or "series" in genre_str or "serie" in genre_str:
            return EPGGenre.SHOW
        elif "sports" in genre_str or "sport" in genre_str:
            return EPGGenre.SPORTS
        elif (
            "children" in genre_str
            or "kids" in genre_str
            or "cartoon" in genre_str
            or "youth" in genre_str
        ):
            return EPGGenre.CHILDRENYOUTH
        elif "documentary" in genre_str or "dokumentation" in genre_str:
            # Documentary can be either News/Current Affairs or Educational/Science
            # We'll use News/Current Affairs as it's more common
            return EPGGenre.NEWSCURRENTAFFAIRS
        elif "music" in genre_str or "ballet" in genre_str or "dance" in genre_str:
            return EPGGenre.MUSICBALLETDANCE
        elif "arts" in genre_str or "culture" in genre_str or "art" in genre_str:
            return EPGGenre.ARTSCULTURE
        elif "educational" in genre_str or "education" in genre_str or "science" in genre_str:
            return EPGGenre.EDUCATIONALSCIENCE
        elif (
            "social" in genre_str
            or "political" in genre_str
            or "politics" in genre_str
            or "economic" in genre_str
        ):
            return EPGGenre.SOCIALPOLITICALECONOMICS
        elif "leisure" in genre_str or "hobbies" in genre_str or "hobby" in genre_str:
            return EPGGenre.LEISUREHOBBIES
        elif "comedy" in genre_str:
            # Comedy is a subtype of Movie/Drama
            return EPGGenre.MOVIEDRAMA
        else:
            return EPGGenre.UNDEFINED

    def parse_programme(
        self,
        programme_elem: ET.Element,
        epg_channel_id: str,
        provider_name: Optional[str] = None,
    ) -> Optional[EPGEntry]:
        """
        Parse a single XMLTV programme element to EPGEntry object.

        Args:
            programme_elem: XML programme element
            epg_channel_id: EPG channel ID for validation
            provider_name: Optional provider name for encoding in broadcast_id

        Returns:
            EPGEntry object, or None if required fields missing or validation fails
        """
        # Verify channel matches
        channel = programme_elem.get("channel", "")
        if channel != epg_channel_id:
            return None

        # Parse required fields
        start_str = programme_elem.get("start", "")
        stop_str = programme_elem.get("stop", "")

        start_time = EPGParser.parse_xmltv_time(start_str)
        end_time = EPGParser.parse_xmltv_time(stop_str)

        if not start_time or not end_time:
            logger.debug(
                f"Programme missing valid start/end time: start={start_str}, stop={stop_str}"
            )
            return None

        # Get title
        title_elem = programme_elem.find("title")
        title = title_elem.text if title_elem is not None and title_elem.text else "Unknown"

        # Generate broadcast ID (with provider encoding if available)
        broadcast_id = EPGParser.generate_broadcast_id(epg_channel_id, start_time, provider_name)

        # Build EPGEntry with required fields
        entry_kwargs: Dict[str, Any] = {
            "broadcast_id": broadcast_id,
            "title": title.strip(),
            "start": start_time,
            "end": end_time,
        }

        # Parse optional fields

        # Sub-title (episode name)
        subtitle_elem = programme_elem.find("sub-title")
        if subtitle_elem is not None and subtitle_elem.text:
            entry_kwargs["episode_name"] = subtitle_elem.text.strip()

        # Description (plot)
        desc_elem = programme_elem.find("desc")
        if desc_elem is not None and desc_elem.text:
            plot = desc_elem.text.strip()
            entry_kwargs["description"] = plot

            # Use first sentence or first 100 chars as plot_outline
            outline = plot.split(".")[0] if "." in plot else plot[:100]
            entry_kwargs["plot_outline"] = outline.strip()

        # Credits
        credits_elem = programme_elem.find("credits")
        if credits_elem is not None:
            # Director
            director_elem = credits_elem.find("director")
            if director_elem is not None and director_elem.text:
                entry_kwargs["directors"] = [director_elem.text.strip()]

            # Actors
            actors = credits_elem.findall("actor")
            if actors:
                cast_list = [actor.text.strip() for actor in actors if actor.text]
                if cast_list:
                    entry_kwargs["cast"] = cast_list

            # Writer
            writer_elem = credits_elem.find("writer")
            if writer_elem is not None and writer_elem.text:
                entry_kwargs["writers"] = [writer_elem.text.strip()]

        # Year/Date
        date_elem = programme_elem.find("date")
        if date_elem is not None and date_elem.text:
            try:
                year = int(date_elem.text.strip()[:4])
                entry_kwargs["year"] = year
            except ValueError:
                pass

        # Category (genre)
        category_elem = programme_elem.find("category")
        if category_elem is not None and category_elem.text:
            genre_str = category_elem.text.strip().lower()
            entry_kwargs["genre"] = EPGParser._map_genre_to_type(genre_str)

        # Icon
        icon_elem = programme_elem.find("icon")
        if icon_elem is not None:
            icon_src = icon_elem.get("src", "")
            if icon_src:
                entry_kwargs["icon"] = icon_src

        # Episode numbering
        episode_nums = programme_elem.findall("episode-num")
        series_num = episode_num = part_num = None

        # Try xmltv_ns first
        for ep_elem in episode_nums:
            if ep_elem.get("system") == "xmltv_ns":
                series_num, episode_num, part_num = EPGParser.parse_episode_num(ep_elem)
                break

        # Fall back to onscreen if xmltv_ns didn't work
        if series_num is None:
            for ep_elem in episode_nums:
                if ep_elem.get("system") == "onscreen":
                    series_num, episode_num, part_num = EPGParser.parse_episode_num(ep_elem)
                    break

        if series_num is not None:
            entry_kwargs["season_number"] = series_num
        if episode_num is not None:
            entry_kwargs["episode_number"] = episode_num
        if part_num is not None:
            entry_kwargs["episode_part_number"] = part_num

        # Star rating
        star_rating_elem = programme_elem.find("star-rating")
        if star_rating_elem is not None:
            rating = EPGParser.parse_star_rating(star_rating_elem)
            if rating is not None:
                entry_kwargs["star_rating"] = rating

        # Parental rating
        rating_elems = programme_elem.findall("rating")
        for rating_elem in rating_elems:
            value_elem = rating_elem.find("value")
            if value_elem is not None and value_elem.text:
                try:
                    # Try to extract numeric rating
                    import re

                    match = re.search(r"\d+", value_elem.text)
                    if match:
                        entry_kwargs["parental_rating"] = int(match.group())
                        break
                except (ValueError, AttributeError):
                    pass

        # Previously shown (first aired)
        prev_shown_elem = programme_elem.find("previously-shown")
        if prev_shown_elem is not None:
            first_aired_str = prev_shown_elem.get("start", "")
            if first_aired_str:
                first_aired = EPGParser.parse_xmltv_time(first_aired_str)
                if first_aired:
                    entry_kwargs["first_aired"] = first_aired

        # Create EPGEntry object with validation
        try:
            return EPGEntry(**entry_kwargs)
        except ValueError as e:
            logger.warning(f"Invalid EPG entry: {e}")
            return None

    @staticmethod
    def open_xml_file(file_path: str):
        """
        Open XML file, handling both plain and gzipped files.

        Args:
            file_path: Path to XML file (can be .xml or .xml.gz)

        Returns:
            File object suitable for ET.iterparse
        """
        if file_path.endswith(".gz"):
            logger.debug(f"Opening gzipped EPG file: {file_path}")
            return gzip.open(file_path, "rt", encoding="utf-8")
        else:
            logger.debug(f"Opening plain EPG file: {file_path}")
            return open(file_path, "r", encoding="utf-8")

    def parse_epg_for_channel(
        self,
        xml_path: str,
        epg_channel_id: str,
        start_time: Optional[int] = None,
        end_time: Optional[int] = None,
        provider_name: Optional[str] = None,
    ) -> List[EPGEntry]:
        """
        Parse EPG data for a specific channel within a time range.
        Uses streaming parse for performance.

        Args:
            xml_path: Path to XMLTV file (can be .xml or .xml.gz)
            epg_channel_id: EPG channel ID to filter for
            start_time: Start of time range (Unix timestamp), None for no lower bound
            end_time: End of time range (Unix timestamp), None for no upper bound
            provider_name: Optional provider name for encoding in broadcast_id

        Returns:
            List of EPGEntry objects
        """
        logger.info(f"Parsing EPG for channel '{epg_channel_id}' from {xml_path}")

        # Register provider once at the beginning (if provided)
        if provider_name and hasattr(self, "_provider_registry"):
            # Check if already registered
            import hashlib

            hash_obj = hashlib.sha256(provider_name.encode("utf-8"))
            provider_hash = int(hash_obj.hexdigest()[:4], 16)

            if provider_hash not in self._provider_registry:
                self._provider_registry[provider_hash] = provider_name
                logger.debug(f"Registered provider '{provider_name}' with hash {provider_hash:04x}")

        programmes: List[EPGEntry] = []

        try:
            with EPGParser.open_xml_file(xml_path) as xml_file:
                # Use iterparse for memory-efficient streaming
                context = ET.iterparse(xml_file, events=("end",))

                for event, elem in context:
                    if elem.tag == "programme":
                        # Check if this programme matches our channel
                        if elem.get("channel") == epg_channel_id:
                            # Parse the programme WITHOUT calling register_provider again
                            epg_entry = self.parse_programme(elem, epg_channel_id, provider_name)

                            if epg_entry:
                                # Filter by time range using EPGEntry methods
                                if start_time is not None and epg_entry.end < start_time:
                                    # Programme ends before requested range
                                    elem.clear()
                                    continue

                                if end_time is not None and epg_entry.start > end_time:
                                    # Programme starts after requested range
                                    # Since XMLTV is chronological, we can stop here
                                    elem.clear()
                                    break

                                programmes.append(epg_entry)

                        # Clear element to free memory
                        elem.clear()

                logger.info(f"Parsed {len(programmes)} programmes for channel '{epg_channel_id}'")
                return programmes

        except ET.ParseError as e:
            logger.error(f"XML parse error in EPG file: {e}")
            return []
        except Exception as e:
            logger.error(f"Error parsing EPG file: {e}")
            return []
