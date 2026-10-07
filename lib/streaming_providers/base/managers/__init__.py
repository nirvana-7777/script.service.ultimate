# streaming_providers/base/managers/__init__.py
"""
Manager ABCs for streaming providers.

Each manager wraps one capability area with a fixed public interface.
Providers subclass and implement the abstract methods; the concrete
methods (headers, DRM defaults, search no-ops) come for free.

Design rules
------------
* All managers share one constructor contract, implemented once in the
  private ManagerBase (managers/_base.py).
* Constructors take four required collaborators -- http_manager, auth,
  country, config -- plus keyword-only extras (caches, collaborators).
* Managers never hold a reference to the provider. Shared state is passed
  in at construction.
* Managers raise from base.errors; nothing catches broadly.
* VOD navigation always returns VodPage (base/vod.py).

On the None-vs-exception rule
-----------------------------
Manager top-level methods signal "this manager doesn't handle that
content_id" by returning None / [] -- NOT by raising NotFoundError.
See providers/_template/README.md for the full rule.

Rigidity note
-------------
The ABCs enforce the *method names and signatures* through the abstract
method mechanism. They do NOT enforce that providers raise the right
error classes, or that they return the right content shapes. Those are
conventions documented in the template.

Manager list
------------
All seven managers are OPTIONAL (see providers/_template/README.md): a
provider wires the ones its service offers and returns None from the other
_build_*() factories. A VOD-only provider has no ChannelManager; a
metadata-only provider may have just an EpgManager.

Core capabilities:
    ChannelManager    (live channels, channel manifest / DRM)
    VodManager        (browseable catalogue)
    EpgManager        (guide data)

Four further capabilities -- providers implement the ones they support:
    RecordingsManager  (cloud / network PVR)
    FavoritesManager    (user bookmarks on programs / channels)
    BookmarksManager    (resume position)
    CatchupManager      (timeshift / restart)

Providers signal a capability's presence by whether _build_*() returns
a manager or None. Capability flags (implements_vod, implements_epg,
implements_recordings, ...) are derived from that.
"""

from .channel import ChannelManager
from .vod import VodManager
from .epg import EpgManager
from .recordings import RecordingsManager
from .favorites import FavoritesManager
from .bookmarks import BookmarksManager
from .catchup import CatchupManager

__all__ = [
    "ChannelManager",
    "VodManager",
    "EpgManager",
    "RecordingsManager",
    "FavoritesManager",
    "BookmarksManager",
    "CatchupManager",
]