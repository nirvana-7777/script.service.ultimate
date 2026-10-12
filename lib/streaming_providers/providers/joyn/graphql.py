# streaming_providers/providers/joyn/graphql.py
# -*- coding: utf-8 -*-
"""
Joyn GraphQL URL builder.

The single place that knows how to turn a persisted-query key plus variables
into an API URL. The hashes and operation names themselves live in
constants.py (GRAPHQL_QUERY_HASHES / GRAPHQL_OPERATIONS); this module is
only the assembler.

Why separate from constants.py: constants is pure data, this is the one bit
of logic over it. Having a single builder means every manager builds the
URL the same way, and if the API ever changes the query-string shape (e.g.
adds a mandatory parameter) there is exactly one place to change.
"""

import json
import urllib.parse
from typing import Any, Dict, Optional

from .constants import (
    GRAPHQL_OPERATIONS,
    GRAPHQL_QUERY_HASHES,
    JOYN_GRAPHQL_BASE_URL,
)


def build_url(operation_key: str, variables: Optional[Dict[str, Any]] = None) -> str:
    """
    Build a persisted-query URL.

    `operation_key` is a key in GRAPHQL_OPERATIONS / GRAPHQL_QUERY_HASHES
    (e.g. "LIVE_CHANNELS"). Both the operationName and the sha256Hash come
    from the constants, so they cannot drift.

    Raises KeyError if operation_key is unknown — that's a programmer error,
    not a runtime condition, so it fails loudly.
    """
    operation_name = GRAPHQL_OPERATIONS[operation_key]
    query_hash = GRAPHQL_QUERY_HASHES[operation_key]

    params = {
        "operationName": operation_name,
        "enable_user_location": "true",
        "watch_assistant_variant": "true",
    }
    if variables:
        params["variables"] = json.dumps(variables, separators=(",", ":"))
    params["extensions"] = json.dumps(
        {"persistedQuery": {"version": 1, "sha256Hash": query_hash}},
        separators=(",", ":"),
    )
    query_string = "&".join(
        f"{k}={urllib.parse.quote(v)}" for k, v in params.items()
    )
    return f"{JOYN_GRAPHQL_BASE_URL}?{query_string}"