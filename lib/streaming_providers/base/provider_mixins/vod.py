"""Provider video-on-demand (VOD) mixin."""

from typing import List, Optional


class ProviderVodMixin:
    @property
    def implements_vod(self) -> bool:
        """
        Indicates whether this provider has a browsable VOD catalogue.

        Return False (and let get_vod_category return []) for providers that
        only offer live channels or events.  VodOperations will skip providers
        where this returns False when aggregating across all providers.
        """
        return False

    def get_vod_category(self, content_id: str = "", **kwargs) -> List:
        """
        Return the children of a VOD tree node.

        Args:
            content_id: Opaque node identifier returned by a previous
                        get_vod_category call.  Empty string → root level.
                        Providers define their own ID format; the caller
                        treats it as an opaque token and never parses it.

        Returns:
            Mixed list of VodCategory and VodItem objects.
            Return [] if the node has no children or VOD is not supported.
        """
        return []

    def search_vod(
        self,
        query: str,
        cursor: Optional[str] = None,
        page_size: int = 24,
        **kwargs,
    ) -> List:
        """
        Search the VOD catalogue for items matching query.

        Args:
            query:     Free-text search string entered by the user.
            cursor:    Opaque continuation token from a previous response's
                       next_cursor field.  None → first page.
            page_size: Hint for how many entries to return per page.
                       Providers may ignore or clamp this value.

        Returns:
            Mixed list of VodCategory and VodItem objects, or a paged dict
            with the same shape as get_vod_category (entries, next_cursor,
            total).  Return [] if search is not supported.
        """
        return []