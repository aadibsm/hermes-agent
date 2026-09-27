"""Opt-in, profile-scoped Codex broker route; never accept a cloud host here."""
from urllib.parse import urlsplit

from agent.secret_scope import get_secret


def codex_broker_route():
    """Return (base_url, bot_key) or None; reject incomplete/unsafe opt-ins."""
    url = get_secret("HERMES_CODEX_BROKER_URL", "") or ""
    key = get_secret("HERMES_CODEX_BROKER_KEY", "") or ""
    if not url:
        if key:
            raise ValueError("Codex broker key configured without URL")
        return None
    parts = urlsplit(url)
    # Numeric loopback only: no DNS rebinding, userinfo, query, fragment,
    # arbitrary subpath or non-HTTP schemes. The broker binds loopback only.
    try:
        port = parts.port
    except ValueError:
        port = None
    if (parts.scheme != "http" or parts.hostname != "127.0.0.1"
            or parts.netloc != f"127.0.0.1:{port}" or not port
            or parts.path not in ("", "/v1") or parts.query or parts.fragment):
        raise ValueError("Codex broker URL must be http://127.0.0.1:<port>/v1")
    if not isinstance(key, str) or len(key) < 32 or any(c.isspace() for c in key):
        raise ValueError("Codex broker requires HERMES_CODEX_BROKER_KEY (32+ nonspace characters)")
    return f"http://127.0.0.1:{port}/v1", key
