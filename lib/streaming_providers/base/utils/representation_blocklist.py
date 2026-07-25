# streaming_providers/base/utils/representation_blocklist.py
from typing import Dict, List, Set
from .logger import logger
from .vfs import get_vfs

class RepresentationBlocklist:
    """
    Manages blocklist of problematic Representation IDs that cause 500 errors.
    """

    def __init__(self, blocklist_path: str = "representation_blocklist.json"):
        self.blocklist_path = blocklist_path
        self.blocklist: Dict[str, Dict[str, List[str]]] = {}
        self._load_blocklist()

    def _load_blocklist(self):
        """Load blocklist from JSON file using VFS."""
        try:
            vfs = get_vfs()
            data = vfs.read_json(self.blocklist_path)

            if data:
                self.blocklist = data
                total_blocked = sum(
                    len(rep_ids)
                    for provider in self.blocklist.values()
                    for rep_ids in provider.values()
                )
#                logger.info(
#                    f"Loaded representation blocklist: "
#                    f"{len(self.blocklist)} providers, {total_blocked} total blocked representations"
#                )
            else:
                logger.info(f"No blocklist found at {self.blocklist_path}, starting with empty blocklist")

        except Exception as e:
            logger.warning(f"Failed to load representation blocklist from {self.blocklist_path}: {e}")
            self.blocklist = {}

    def is_blocked(self, provider: str, channel: str, representation_id: str) -> bool:
        """Check if a representation ID is blocked for a given provider/channel."""
        if not provider or not channel:
            return False

        provider_data = self.blocklist.get(provider, {})
        channel_data = provider_data.get(channel, [])

        return representation_id in channel_data

    def get_blocked_ids(self, provider: str, channel: str) -> Set[str]:
        """Get set of all blocked representation IDs for a provider/channel."""
        if not provider or not channel:
            return set()

        provider_data = self.blocklist.get(provider, {})
        channel_data = provider_data.get(channel, [])

        return set(channel_data)