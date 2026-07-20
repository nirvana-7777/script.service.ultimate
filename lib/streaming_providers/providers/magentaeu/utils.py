# streaming_providers/providers/magentaeu/utils.py

from .constants import build_guest_headers, _generate_txn_id

# Re-export for backward compatibility. These are the only two names that
# were previously defined here (verified against the prior utils.py before
# this change) -- both now live in constants.py alongside the rest of the
# header-generation logic (build_auth_headers, build_headers_with_txn),
# giving a single source of truth for all request headers.
__all__ = [
    "build_guest_headers",
    "_generate_txn_id",
]