# streaming_providers/providers/hrti/ids.py
"""
The ONE place that knows the HRTi content-id grammar. Both managers'
handles_content_id() call these predicates, so they are complementary by
construction (README §7). Pure functions, no I/O.

Grammar
-------
  ""                          VOD root (navigation, not playable)
  "catalogue_<ref>"           VOD folder            (navigation)
  "series_<sid>--<ssid>"      VOD series season     (navigation)
  "special_watch_later"       VOD special list      (navigation)
  "special_editors_choice"    VOD special list      (navigation)
  "details_<ref>"             one playable VOD item (explicit)
  "<ref>"  not purely digits  one playable VOD item (UUID or "1870699590_delin")
  "<digits>"                  live channel / radio  (e.g. "40013")

Navigation ids are claimed by NEITHER manager for playback: they are browsed
through get_vod_category, which the backend calls directly.
"""

NAV_PREFIXES = ("catalogue_", "series_", "special_")
DETAILS_PREFIX = "details_"


def is_nav(content_id: str) -> bool:
    return any(content_id.startswith(p) for p in NAV_PREFIXES)


def is_live(content_id: str) -> bool:
    return bool(content_id) and content_id.isdigit()


def is_vod(content_id: str) -> bool:
    if not content_id or is_nav(content_id):
        return False
    if content_id.startswith(DETAILS_PREFIX):
        return True
    return not content_id.isdigit()


def vod_ref(content_id: str) -> str:
    """The bare ReferenceId of a playable VOD id (strips ``details_``)."""
    if content_id.startswith(DETAILS_PREFIX):
        return content_id[len(DETAILS_PREFIX):]
    return content_id
