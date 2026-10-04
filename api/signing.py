"""
api/signing.py — HMAC URL signing and verification for TeraBridge proxy URLs.

Provides time-limited, tiered HMAC signatures for download, stream, segment,
and thumbnail proxy URLs so clients don't need to re-send the API key on
every sub-request.
"""
import hashlib
import hmac
import logging
import time

from fastapi import Request

from api.config import HMAC_SECRET, TIERED_SIGNATURE_TTLS, DEFAULT_SIGNATURE_TTL
from api.auth import get_user_tier

logger = logging.getLogger("terabridge.signing")


def signature_ttl_for(kind: str, tier: str = "free") -> int:
    """Return the HMAC TTL in seconds for the given URL kind and user tier."""
    ttls = TIERED_SIGNATURE_TTLS.get(tier, TIERED_SIGNATURE_TTLS["free"])
    return ttls.get(kind, DEFAULT_SIGNATURE_TTL)


def generate_signature(param1: str, param2: str, param3: str = "", exp: str | int = "") -> str:
    """
    Produce an HMAC-SHA256 hex digest over the canonical message.

    Message format:
      With expiry  → "<param1>|<param2>|<param3>|<exp>"
      Without      → "<param1>|<param2>|<param3>"
    """
    if not HMAC_SECRET:
        return ""
    message = (
        f"{param1}|{param2}|{param3}|{exp}"
        if exp != ""
        else f"{param1}|{param2}|{param3}"
    )
    return hmac.new(HMAC_SECRET.encode(), message.encode(), hashlib.sha256).hexdigest()


def make_signed_params(
    request: Request,
    param1: str,
    param2: str,
    param3: str = "",
    kind: str = "download",
) -> str:
    """
    Build the ``sig=…&exp=…`` query-string fragment for a proxy URL.

    The TTL is chosen based on the authenticated user's tier so premium users
    receive longer-lived links.
    """
    if not HMAC_SECRET:
        return ""
    tier = get_user_tier(request)
    exp = int(time.time()) + signature_ttl_for(kind, tier)
    sig = generate_signature(param1, param2, param3, exp)
    return f"sig={sig}&exp={exp}"


def verify_signature(
    param1: str,
    param2: str,
    param3: str,
    signature: str,
    exp: str | int = "",
) -> bool:
    """
    Verify an HMAC signature produced by :func:`generate_signature`.

    Accepts both the current expiring format (with ``exp``) and the legacy
    non-expiring format for backwards compatibility.  Legacy acceptance is
    logged at WARNING level.
    """
    if not signature or not HMAC_SECRET:
        return False

    if exp:
        try:
            if int(exp) < int(time.time()):
                return False
        except (TypeError, ValueError):
            return False

        expected = generate_signature(param1, param2, param3, exp)
        if not expected:
            return False
        return hmac.compare_digest(expected, signature)

    # Legacy: unsigned / no-expiry URLs
    expected_legacy = generate_signature(param1, param2, param3, "")
    if expected_legacy and hmac.compare_digest(expected_legacy, signature):
        logger.warning(
            "Accepted legacy un-expiring signed URL (p1=%s...). "
            "Consider re-resolving to refresh.",
            param1[:24],
        )
        return True

    return False
