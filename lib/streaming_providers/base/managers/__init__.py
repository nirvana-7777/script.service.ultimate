# streaming_providers/base/managers/__init__.py
"""
Manager ABCs for streaming providers.

Each manager wraps one capability area (channels, VOD, EPG) with a fixed
public interface. Providers subclass and implement the abstract methods;
the concrete methods (headers, DRM defaults, search no-ops) come for free.

Design rules
------------
* Constructors take four required collaborators -- http_manager, auth,
  country, config -- plus keyword-only extras (caches, collaborators).
* Managers never hold a reference to the provider. Shared state is passed
  in at construction.
* Managers raise from base.errors; nothing catches broadly.
* VOD navigation always returns VodPage (base/vod.py).

On the None-vs-exception rule
-----------------------------
Manager top-level methods (get_*_manifest, get_*_drm) signal "this manager
doesn't handle that content_id" by returning None / [] -- NOT by raising
NotFoundError. See providers/_template/README.md for the full rule.

Rigidity note
-------------
The ABCs enforce the *method names and signatures* through the abstract
method mechanism. They do NOT enforce that providers raise the right
error classes, or that they return the right content shapes. Those are
conventions documented in the template. Treat the ABCs as "the interface
is fixed" not as "everything about a manager is enforced."
"""

from .channel import ChannelManager
from .vod import VodManager
from .epg import EpgManager

__all__ = ["ChannelManager", "VodManager", "EpgManager"]