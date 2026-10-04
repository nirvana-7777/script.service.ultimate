# streaming_providers/providers/simpli/recordings_manager.py
"""
simpliTV recordings manager.

Recording identity (kept strictly separate from content identity):

    recording_id  -- the provider's recording id. This is what
                     delete_recording receives. It is NOT a content_id.

    content_id    -- "rec:<programme codename>". This is what
                     get_manifest receives to play the recording. The
                     channel manager resolves it (same AcquireContent
                     call as live).

This manager does not implement get_manifest -- do not add a parallel
manifest path here.

get_recordings() returns SimpliTVChannel objects whose content_id is the
"rec:..." id and whose recording_id carries the provider's id. Only
recordings whose recording_status is "Recorded" are playable;
"Scheduled" and "Failed" are listed but must not be played.

Note on construction: the base Content dataclass declares `content_id`
and a required `provider` field. `Channel.channel_id` is a property
that proxies to `content_id`, but dataclass __init__ bypasses
properties, so SimpliTVChannel is built with `content_id=` and
`provider=`.

Scheduling needs a *programme* codename (the EPG tile's own codename),
not a channel codename: pass prog:<programme codename>.
"""

from typing import Dict, List, Optional

from ...base.errors import BadRequestError
from ...base.managers import RecordingsManager
from ...base.models import Channel
from ...base.utils.logger import logger

from .channel_manager import parse_programme_id
from .constants import SimpliTVDefaults
from .helpers import transport_errors
from .models import SimpliTVChannel


class SimpliTVRecordingsManager(RecordingsManager):
    """NPvR recordings for simpliTV."""

    def __init__(
        self,
        *,
        http_manager,
        auth,
        country,
        config,
        recordings_cache: Optional[dict] = None,
    ):
        super().__init__(
            http_manager=http_manager,
            auth=auth,
            country=country,
            config=config,
        )
        self._recordings_cache = (
            recordings_cache if recordings_cache is not None else {}
        )

    # ------------------------------------------------------------------
    # Abstract methods
    # ------------------------------------------------------------------

    def get_recordings(self, **kw) -> List[Channel]:
        """
        Return all NPvR recordings across every page ([] if none).

        The page index base is unverified (the addon's own paging is
        broken and limit=99999 normally returns everything in one page),
        so the walk is bounded by the reported totalPages and
        de-duplicated by recording id: a page that adds nothing new ends
        the walk instead of looping or returning duplicates.
        """
        found: Dict[str, SimpliTVChannel] = {}
        page = 0
        while True:
            # NOTE: GetRecordings names the token parameter `tokenValue`;
            # the token is in the URL, not a header.
            url = self.auth.with_token(
                self.config.get_recordings_url(),
                {
                    "platformCodename": self.config.platform_codename,
                    "page": page,
                    "limit": 99999,
                    "recordingType": "NPvr",
                    "recordingFlags": (
                        "Programs,ProgramImages,ProgramCategories"
                    ),
                },
                param=SimpliTVDefaults.TOKEN_PARAM_RECORDINGS,
            )
            resp = self.http_manager.get(
                url, headers=self.config.get_api_headers()
            )
            data = resp.json()

            total_pages = (data.get("pagination") or {}).get("totalPages", 0)
            if total_pages == 0:
                break

            added = 0
            for rec in data.get("recordings", []):
                channel = self._rec_to_channel(rec)
                key = channel.recording_id or (
                    f"{channel.codename}:{channel.current_start}"
                )
                if key not in found:
                    found[key] = channel
                    added += 1

            page += 1
            if page >= total_pages:
                break
            if added == 0:
                logger.warning(
                    f"simpliTV: GetRecordings page {page} added no new "
                    f"recordings (totalPages={total_pages}); stopping"
                )
                break
        return list(found.values())

    def delete_recording(self, recording_id: str, **kw) -> None:
        """
        Delete a recording by recording_id.

        Raises:
            KeyError:    if the recording does not exist / was not deleted.
            ProviderError subclasses: on transport / backend failure
                         (typed errors such as AuthError pass through).
        """
        if not recording_id:
            raise KeyError("simpliTV: empty recording_id")

        # NOTE: token is in the body (auth_body), not a header.
        body = self.auth.auth_body({
            "platformCodename": self.config.platform_codename,
            "recordingId": recording_id,
        })
        with transport_errors("delete_recording"):
            resp = self.http_manager.post(
                self.config.delete_recording_url(),
                json=body,
                headers=self.config.get_api_headers(),
            )
            data = resp.json()

        # The API answers 200 with success:false for "not found";
        # silently returning would hide real backend errors.
        if not (data.get("result") or {}).get("success", False):
            raise KeyError(
                f"simpliTV: recording {recording_id!r} not deleted "
                f"(response: {data!r})"
            )

    # ------------------------------------------------------------------
    # Optional override -- scheduling
    # ------------------------------------------------------------------

    def schedule_recording(self, content_id: str, **kw) -> bool:
        """
        Schedule a recording of a programme.

        content_id must be prog:<programme codename>. Channel ids
        (live:, catchup:) identify a channel, not a programme, and
        cannot be scheduled; rec: ids are already recordings.
        """
        if not content_id.startswith(SimpliTVDefaults.PROGRAMME_PREFIX):
            raise BadRequestError(
                f"simpliTV: scheduling needs a prog:<programme codename> "
                f"id, got {content_id!r}"
            )
        codename = parse_programme_id(content_id)

        body = self.auth.auth_body({
            "platformCodename": self.config.platform_codename,
            "EpgId": {"Codename": codename},
        })
        with transport_errors("schedule_recording"):
            resp = self.http_manager.post(
                self.config.schedule_recording_url(),
                json=body,
                headers=self.config.get_api_headers(),
            )
            data = resp.json()
        return bool((data.get("result") or {}).get("success", False))

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _rec_to_channel(self, rec: dict) -> SimpliTVChannel:
        """
        Map one GetRecordings entry to SimpliTVChannel.

        content_id is "rec:<programme codename>" (the id used to play
        the recording); recording_id is the provider's id (the id used
        to delete it). They are different namespaces.
        """
        programme = rec.get("program") or {}
        codename = programme.get("codename", "")
        return SimpliTVChannel(
            name=programme.get("title", codename),
            content_id=f"{SimpliTVDefaults.RECORDING_PREFIX}{codename}",
            provider=SimpliTVDefaults.PROVIDER_NAME,
            codename=codename,
            current_programme=programme.get("title", ""),
            current_start=programme.get("start", ""),
            current_stop=programme.get("stop", ""),
            recording_id=rec.get("recordingId", ""),
            recording_status=rec.get("status", ""),
        )