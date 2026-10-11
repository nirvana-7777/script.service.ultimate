# streaming_providers/providers/joyn/config.py
# -*- coding: utf-8 -*-
"""
Joyn provider configuration — the single config object, shared by every layer.

One instance is created by JoynProvider and passed to auth, session, the
entitlement helper and every manager. Never rebuild a second config from a
subset of values: that is how header drift between layers happens, and Joyn
used to have exactly that bug (JoynAuthenticator defined its own local
JoynConfig class, with a slightly different distribution_tenant computation).

Header builders live here, not in the managers, so the difference between the
four Joyn header sets is visible in one place:

  * graphql_headers()           GraphQL API (joyn-* headers, optional bearer)
  * api_headers(token)          entitlement / playlist (bearer + joyn-*)
  * entitlement_headers(token)  entitlement host ONLY (bearer, NO joyn-*)
  * cdn_headers()               MPD/segment fetch by the player (NO bearer)

The CDN deliberately receives no Authorization header: the manifest URL is
self-authorizing, and sending the Joyn bearer to the CDN returns
"400 InvalidArgument: Unsupported Authorization Type".
"""

from typing import Dict, Optional

from .constants import (
    COUNTRY_TENANT_MAPPING,
    DEFAULT_COUNTRY,
    DEFAULT_MAX_RETRIES,
    DEFAULT_PLATFORM,
    DEFAULT_REQUEST_TIMEOUT,
    JOYN_API_BASE_HEADERS,
    JOYN_CLIENT_VERSION,
    JOYN_DOMAINS,
    JOYN_GRAPHQL_BASE_HEADERS,
    JOYN_USER_AGENT,
)


class JoynConfig:
    """
    Per-instance configuration. One instance, shared by every collaborator.

    country is normalised to lowercase here: the registry constructs
    multi-country providers with the lowercase entry from SUPPORTED_COUNTRIES
    ("de"/"at"/"ch"), but the class-level default and ad-hoc callers may pass
    "DE". Everything downstream (JOYN_DOMAINS, COUNTRY_TENANT_MAPPING,
    JOYN_USER_AGENT's Origin) keys by lowercase.
    """

    def __init__(self, country=DEFAULT_COUNTRY, platform=DEFAULT_PLATFORM,
                 timeout=DEFAULT_REQUEST_TIMEOUT, max_retries=DEFAULT_MAX_RETRIES):
        self._country = country.lower()
        self.platform = platform
        self.timeout = timeout
        self.max_retries = max_retries
        self.user_agent = JOYN_USER_AGENT
        self.base_website = JOYN_DOMAINS.get(self._country, JOYN_DOMAINS["de"])
        self.distribution_tenant = COUNTRY_TENANT_MAPPING.get(self._country, "JOYN")

    @property
    def country(self) -> str:
        return self._country

    @country.setter
    def country(self, value: str) -> None:
        self._country = value.lower()
        self.base_website = JOYN_DOMAINS.get(self._country, JOYN_DOMAINS["de"])
        self.distribution_tenant = COUNTRY_TENANT_MAPPING.get(self._country, "JOYN")

    # ------------------------------------------------------------------
    # URL builders (no f-strings with hosts anywhere else)
    # ------------------------------------------------------------------

    def website(self) -> str:
        return JOYN_DOMAINS.get(self.country, JOYN_DOMAINS["de"])

    def oauth_redirect_uri(self) -> str:
        return f"https://www.joyn.{self.country}/oauth"

    # ------------------------------------------------------------------
    # Header builders
    # ------------------------------------------------------------------

    def _joyn_common(self) -> Dict[str, str]:
        return {
            "joyn-client-version": JOYN_CLIENT_VERSION,
            "joyn-country": self.country.upper(),
            "joyn-distribution-tenant": self.distribution_tenant,
            "joyn-platform": self.platform,
        }

    def graphql_headers(
        self,
        token: Optional[str] = None,
        authenticated: bool = False,
    ) -> Dict[str, str]:
        """
        GraphQL API headers.

        joyn-user-state is R_A when a bearer is present, A_A otherwise — the
        API uses this to decide whether to serve user-specific lanes. The
        current channel_manager hardcodes R_A; that is only correct when the
        caller is authenticated. Passing `authenticated=True` without a token
        would be a contradiction and logs a warning upstream, not here.
        """
        headers = JOYN_GRAPHQL_BASE_HEADERS.copy()
        headers.update(self._joyn_common())
        headers["joyn-user-state"] = "code=R_A" if authenticated else "code=A_A"
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def api_headers(self, token: str) -> Dict[str, str]:
        """
        API headers for GraphQL that expect a bearer (VOD navigation,
        user state, search). Distinct from entitlement_headers() because the
        entitlement host rejects the joyn-* header set.
        """
        headers = JOYN_API_BASE_HEADERS.copy()
        headers.update(self._joyn_common())
        headers.update({
            "joyn-b2b-context": "UNKNOWN",
            "joyn-client-os": "UNKNOWN",
            "origin": self.website(),
            "Authorization": f"Bearer {token}",
        })
        return headers

    @staticmethod
    def entitlement_headers(token: str) -> Dict[str, str]:
        """
        Entitlement host: minimal headers only.

        The entitlement service lives on a separate host that does not accept
        the joyn-* set. Sending them causes 400s. Matching the working
        reference client: bearer + JSON content type + a plain User-Agent.
        The bare "Mozilla/5.0" (not JOYN_USER_AGENT) is deliberate — the
        reference client does not send the full browser UA to this host.
        """
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "Mozilla/5.0",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def cdn_headers(self) -> Dict[str, str]:
        """
        Headers for the CDN-served manifest and segments.

        No Authorization on purpose: the manifest URL is self-authorizing
        (the signature is in the query string), and the CDN rejects any
        Authorization header with a 400.
        """
        return {
            "User-Agent": JOYN_USER_AGENT,
            "Origin": self.website(),
        }

    def drm_license_headers(self) -> Dict[str, str]:
        """
        License-request headers for Widevine.

        No Authorization: the license URL carries its own signature. Origin
        and User-Agent are required by the Cloudflare WAF in front of the
        license endpoint — omitting them yields a challenge page, not a
        license.
        """
        return {
            "User-Agent": JOYN_USER_AGENT,
            "Origin": self.website(),
            "Content-Type": "application/octet-stream",
        }

    # ------------------------------------------------------------------
    # Convenience accessors (used by entitlement, playlist, VOD managers)
    # ------------------------------------------------------------------

    @property
    def is_german(self) -> bool:
        """True for the DE tenant; a few endpoints are DE-only."""
        return self.country == "de"