# streaming_providers/base/utils/drm_key_manager.py
from dataclasses import dataclass, field
from typing import Dict, Optional
from .logger import logger

@dataclass
class KeyConfiguration:
    """Configuration for DRM key management with validation and normalization."""
    keys: Dict[str, str] = field(default_factory=dict)
    single_key_mode: bool = field(init=False)
    default_kid: Optional[str] = field(init=False, default=None)
    default_key: Optional[str] = field(init=False, default=None)

    def __post_init__(self):
        """Normalize and validate keys on initialization."""
        normalized = {}
        for kid, key in self.keys.items():
            norm_kid = kid.replace("-", "").lower()
            norm_key = key.replace("-", "").lower()

            # Validate hex format (32 characters = 16 bytes)
            if len(norm_kid) != 32 or not all(c in '0123456789abcdef' for c in norm_kid):
                logger.warning(f"Invalid KID format (expected 32 hex chars): {kid}")
                continue
            if len(norm_key) != 32 or not all(c in '0123456789abcdef' for c in norm_key):
                logger.warning(f"Invalid key format for KID {kid}: {key}")
                continue

            normalized[norm_kid] = norm_key

        self.keys = normalized
        self.single_key_mode = len(self.keys) <= 1

        if self.single_key_mode and self.keys:
            self.default_kid, self.default_key = next(iter(self.keys.items()))
            logger.debug(f"Single key mode: KID={self.default_kid[:8]}...")
        elif self.keys:
            logger.debug(f"Multi-key mode: {len(self.keys)} keys available")