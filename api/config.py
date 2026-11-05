"""
api/config.py — Centralised environment configuration for TeraBridge API.
All env-var reads live here; every other module imports from this file.
"""
import os
import ipaddress
import logging

# Load .env if present
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

logger = logging.getLogger("terabridge.config")

def _get_int(key: str, default: int) -> int:
    val = os.environ.get(key)
    if val is None or val.strip() == "":
        return default
    try:
        return int(val.strip())
    except (ValueError, TypeError):
        logger.warning("Invalid integer for env var %s=%r; using default %d", key, val, default)
        return default

def _get_bool(key: str, default: bool) -> bool:
    val = os.environ.get(key)
    if val is None:
        return default
    return val.strip().lower() not in ("0", "false", "no", "off")

# ─── Core API settings ────────────────────────────────────────────────
API_KEY         = os.environ.get("API_KEY")
_explicit_hmac  = os.environ.get("HMAC_SECRET")
if _explicit_hmac:
    HMAC_SECRET = _explicit_hmac
elif API_KEY:
    logger.warning(
        "HMAC_SECRET is unset; falling back to API_KEY. "
        "In production, set HMAC_SECRET separately to prevent cascading key compromise."
    )
    HMAC_SECRET = API_KEY
else:
    logger.warning("Neither HMAC_SECRET nor API_KEY is set. URL signatures will be disabled or insecure.")
    HMAC_SECRET = None

REQUIRE_API_KEY = _get_bool("REQUIRE_API_KEY", True)
CRON_SECRET     = os.environ.get("CRON_SECRET")

# ─── Cache ────────────────────────────────────────────────────────────
CACHE_TTL_SECONDS     = _get_int("CACHE_TTL", 300)
CACHE_MAX_ENTRIES     = _get_int("CACHE_MAX_ENTRIES", 512)
CACHE_THUMBNAIL_TTL   = _get_int("CACHE_THUMBNAIL_TTL", 86400)
CACHE_DASHBOARD_TTL   = _get_int("CACHE_DASHBOARD_TTL", 60)

# ─── Rate limiting ────────────────────────────────────────────────────
RATE_LIMIT_RPM        = _get_int("RATE_LIMIT_RPM", 30)
RATE_LIMIT_WINDOW     = _get_int("RATE_LIMIT_WINDOW", 60)  # seconds
AUTH_RATE_LIMIT_RPM   = _get_int("AUTH_RATE_LIMIT_RPM", 10)  # max failed auth attempts before lockout
AUTH_LOCKOUT_SECONDS  = _get_int("AUTH_LOCKOUT_SECONDS", 60)  # lockout duration for failed auth
RATE_LIMIT_MEDIA_RPM  = _get_int("RATE_LIMIT_MEDIA_RPM", 180)  # allowance for stream segments / thumbnails

# ─── Request limits & Timeouts ───────────────────────────────────────
MAX_REQUEST_BODY_SIZE_BYTES = _get_int("MAX_REQUEST_BODY_SIZE_BYTES", 5 * 1024 * 1024)  # 5 MB
REQUEST_TIMEOUT_SECONDS     = _get_int("REQUEST_TIMEOUT_SECONDS", 60)  # 60s max per API request

# ─── HMAC signature TTLs (seconds) ───────────────────────────────────
TIERED_SIGNATURE_TTLS = {
    "free": {
        "segment":   _get_int("SIG_TTL_SEGMENT_FREE",   30 * 60),
        "download":  _get_int("SIG_TTL_DOWNLOAD_FREE",  2 * 3600),
        "manifest":  _get_int("SIG_TTL_MANIFEST_FREE",  24 * 3600),
        "thumbnail": _get_int("SIG_TTL_THUMBNAIL_FREE", 24 * 3600),
    },
    "premium": {
        "segment":   _get_int("SIG_TTL_SEGMENT_PREMIUM",   2 * 3600),
        "download":  _get_int("SIG_TTL_DOWNLOAD_PREMIUM",  24 * 3600),
        "manifest":  _get_int("SIG_TTL_MANIFEST_PREMIUM",  30 * 24 * 3600),
        "thumbnail": _get_int("SIG_TTL_THUMBNAIL_PREMIUM", 30 * 24 * 3600),
    },
}
DEFAULT_SIGNATURE_TTL = _get_int("SIG_TTL_DEFAULT", 24 * 3600)

# ─── Firebase ─────────────────────────────────────────────────────────
FIREBASE_PROJECT_ID = (
    os.environ.get("VITE_FIREBASE_PROJECT_ID")
    or os.environ.get("FIREBASE_PROJECT_ID")
    or None
)

# ─── Platform detection ───────────────────────────────────────────────
ON_VERCEL = bool(os.environ.get("VERCEL"))
ON_RENDER = (
    os.environ.get("RENDER", "").lower() in ("true", "1", "yes")
    or "RENDER_SERVICE_ID" in os.environ
)

# ─── Trusted proxy CIDRs ─────────────────────────────────────────────
TRUSTED_PROXY_CIDRS_RAW = os.environ.get("TRUSTED_PROXIES", "").strip()

def _parse_trusted_cidrs(raw: str):
    cidrs = []
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            cidrs.append(ipaddress.ip_network(entry, strict=False))
        except ValueError as exc:
            logger.warning("Ignoring invalid TRUSTED_PROXIES entry %r: %s", entry, exc)
    return cidrs

TRUSTED_PROXY_CIDRS = _parse_trusted_cidrs(TRUSTED_PROXY_CIDRS_RAW)

# ─── CORS ─────────────────────────────────────────────────────────────
ALLOWED_ORIGINS_RAW = os.environ.get("ALLOWED_ORIGINS", "").strip()
ALLOWED_ORIGINS = frozenset(
    o.strip().rstrip("/") for o in ALLOWED_ORIGINS_RAW.split(",") if o.strip()
)

# ─── Misc ─────────────────────────────────────────────────────────────
REDIRECT_SEGMENTS        = os.environ.get("REDIRECT_SEGMENTS", "False").lower() in ("true", "1")
NOTIFICATION_WEBHOOK_URL = os.environ.get("NOTIFICATION_WEBHOOK_URL")
CONFIG_CHECK_INTERVAL    = 60  # seconds between dynamic config refreshes
ALLOW_LEGACY_SIGNATURES  = _get_bool("ALLOW_LEGACY_SIGNATURES", False)
RESOLVE_TIMEOUT_SECONDS  = _get_int("RESOLVE_TIMEOUT_SECONDS", 60)

# ─── Outbound TeraBox Proxy (Bypasses Datacenter IP Blocks / CAPTCHA) ──
OUTBOUND_PROXY = (
    os.environ.get("TERABOX_OUTBOUND_PROXY")
    or os.environ.get("OUTBOUND_PROXY")
    or os.environ.get("HTTPS_PROXY")
    or os.environ.get("HTTP_PROXY")
    or None
)
PROXY_DOWNLOADS = os.environ.get("PROXY_DOWNLOADS", "false").lower() in ("true", "1", "yes")

# ─── Allowed outbound stream hosts (SSRF allowlist) ───────────────────
ALLOWED_STREAM_SUFFIXES = (
    ".1024terabox.com", ".terabox.com", ".teraboxapp.com", ".terabox.app", ".baidu.com",
    ".freeterabox.com", ".nephobox.com", ".momerybox.com", ".mirrobox.com", ".gibibox.com",
    ".tibibox.com", ".4funbox.com", ".1024tera.com", ".1024nephobox.com", ".terabox.fun",
    ".terasharefile.com", ".teraboxlink.com", ".teraboxshare.com",
    ".terasharelink.com", ".terafileshare.com", ".teraboxurl.com", ".terabox.club",
    ".terabox.me", ".terashare.net", ".boxtera.com", ".terafiles.net",
    ".baidupcs.com", ".downloadaidl.com", ".dubox.com",
    ".1024terabox.com-videotran-hybcloud", ".terabox.com-videotran-hybcloud",
    ".teraboxapp.com-videotran-hybcloud", ".terabox.app-videotran-hybcloud",
    ".freeterabox.com-videotran-hybcloud", ".nephobox.com-videotran-hybcloud",
    ".momerybox.com-videotran-hybcloud", ".mirrobox.com-videotran-hybcloud",
    ".gibibox.com-videotran-hybcloud", ".teraboxshare.com-videotran-hybcloud",
    ".tibibox.com-videotran-hybcloud", ".4funbox.com-videotran-hybcloud",
    ".1024tera.com-videotran-hybcloud", ".1024nephobox.com-videotran-hybcloud",
    ".terabox.fun-videotran-hybcloud", ".terasharefile.com-videotran-hybcloud",
    ".teraboxlink.com-videotran-hybcloud", ".terasharelink.com-videotran-hybcloud",
    ".terafileshare.com-videotran-hybcloud", ".teraboxurl.com-videotran-hybcloud",
    ".terabox.club-videotran-hybcloud", ".terabox.me-videotran-hybcloud",
    ".downloadaidl.com-videotran-hybcloud", ".dubox.com-videotran-hybcloud",
    ".koofr.net", ".koofr.eu", "pcs.baidu.com", "d.pcs.1024terabox.com",
)
