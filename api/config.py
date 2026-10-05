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

# ─── Core API settings ────────────────────────────────────────────────
API_KEY        = os.environ.get("API_KEY")
HMAC_SECRET    = os.environ.get("HMAC_SECRET") or API_KEY
REQUIRE_API_KEY = os.environ.get("REQUIRE_API_KEY", "auto").lower() not in ("0", "false", "no")
CRON_SECRET    = os.environ.get("CRON_SECRET")

# ─── Cache ────────────────────────────────────────────────────────────
CACHE_TTL_SECONDS     = int(os.environ.get("CACHE_TTL", 300))
CACHE_MAX_ENTRIES     = int(os.environ.get("CACHE_MAX_ENTRIES", 512))
CACHE_THUMBNAIL_TTL   = int(os.environ.get("CACHE_THUMBNAIL_TTL", 86400))
CACHE_DASHBOARD_TTL   = int(os.environ.get("CACHE_DASHBOARD_TTL", 60))

# ─── Rate limiting ────────────────────────────────────────────────────
RATE_LIMIT_RPM    = int(os.environ.get("RATE_LIMIT_RPM", 30))
RATE_LIMIT_WINDOW = 60  # seconds

# ─── HMAC signature TTLs (seconds) ───────────────────────────────────
TIERED_SIGNATURE_TTLS = {
    "free": {
        "segment":   int(os.environ.get("SIG_TTL_SEGMENT_FREE",   30 * 60)),
        "download":  int(os.environ.get("SIG_TTL_DOWNLOAD_FREE",  2 * 3600)),
        "manifest":  int(os.environ.get("SIG_TTL_MANIFEST_FREE",  24 * 3600)),
        "thumbnail": int(os.environ.get("SIG_TTL_THUMBNAIL_FREE", 24 * 3600)),
    },
    "premium": {
        "segment":   int(os.environ.get("SIG_TTL_SEGMENT_PREMIUM",   2 * 3600)),
        "download":  int(os.environ.get("SIG_TTL_DOWNLOAD_PREMIUM",  24 * 3600)),
        "manifest":  int(os.environ.get("SIG_TTL_MANIFEST_PREMIUM",  30 * 24 * 3600)),
        "thumbnail": int(os.environ.get("SIG_TTL_THUMBNAIL_PREMIUM", 30 * 24 * 3600)),
    },
}
DEFAULT_SIGNATURE_TTL = int(os.environ.get("SIG_TTL_DEFAULT", 24 * 3600))

# ─── Firebase ─────────────────────────────────────────────────────────
FIREBASE_PROJECT_ID = (
    os.environ.get("VITE_FIREBASE_PROJECT_ID")
    or os.environ.get("FIREBASE_PROJECT_ID")
    or "teraplay-project"
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

# ─── Allowed outbound stream hosts (SSRF allowlist) ───────────────────
ALLOWED_STREAM_SUFFIXES = (
    ".1024terabox.com", ".terabox.com", ".teraboxapp.com", ".terabox.app", ".baidu.com",
    ".freeterabox.com", ".nephobox.com", ".momerybox.com", ".mirrobox.com", ".gibibox.com",
    ".tibibox.com", ".4funbox.com", ".1024tera.com", ".1024nephobox.com", ".terabox.fun",
    ".terasharefile.com", ".teraboxlink.com", ".teraboxshare.com",
    ".1024terabox.com-videotran-hybcloud", ".terabox.com-videotran-hybcloud",
    ".teraboxapp.com-videotran-hybcloud", ".terabox.app-videotran-hybcloud",
    ".freeterabox.com-videotran-hybcloud", ".nephobox.com-videotran-hybcloud",
    ".momerybox.com-videotran-hybcloud", ".mirrobox.com-videotran-hybcloud",
    ".gibibox.com-videotran-hybcloud", ".teraboxshare.com-videotran-hybcloud",
    ".tibibox.com-videotran-hybcloud", ".4funbox.com-videotran-hybcloud",
    ".1024tera.com-videotran-hybcloud", ".1024nephobox.com-videotran-hybcloud",
    ".terabox.fun-videotran-hybcloud", ".terasharefile.com-videotran-hybcloud",
    ".teraboxlink.com-videotran-hybcloud",
    ".koofr.net", ".koofr.eu", "pcs.baidu.com", "d.pcs.1024terabox.com",
)
