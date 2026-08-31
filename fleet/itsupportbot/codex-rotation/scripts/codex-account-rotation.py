#!/usr/bin/env python3
"""Hourly Codex OAuth seeding rotation.

Checks all three configured OAuth credentials. In each upstream usage window,
sends exactly one tiny successful Codex prompt per credential, then advances to
the next. It does not wait for the coarse usage meter to round up to 1%.
After all three windows have been touched, it returns to the preferred
credential and makes no more synthetic calls until a new window is detected.
The job is deliberately profile-local; it never copies credentials into other
profiles.

Normal successful cron runs are silent. Use --report for a status summary.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import fcntl
import json
import math
import os
import secrets
import selectors
import stat
import subprocess  # nosec B404 - argv, cwd, and shell mode are fixed below
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BASE = Path("/home/hermes/.hermes")
PROFILE_ROOT = BASE / "profiles"
LOCAL_PROFILE = "itsupportbot"
LOCAL_ROOT = PROFILE_ROOT / LOCAL_PROFILE
STATE_PATH = LOCAL_ROOT / "state/codex-account-rotation.json"
LOG_PATH = LOCAL_ROOT / "logs/codex-account-rotation.log"
LOCK_PATH = LOCAL_ROOT / "state/codex-account-rotation.lock"
PROFILE_USAGE_CACHE = LOCAL_ROOT / "state/codex-usage.json"
ORDER = ["tabiaadib", "smaadibusa", "aadibsmusa1"]
OAUTH1 = "tabiaadib"
# Preserve the preferred slot under its retained exact label.
PREFERRED = "aadibsmusa1"
SMOKE_PROFILE = LOCAL_PROFILE
HERMES_BIN = Path("/home/hermes/.hermes/hermes-agent/venv/bin/hermes")  # cron PATH lacks ~/.local/bin
USAGE_URL = "https://chatgpt.com/backend-api/wham/usage"
SMOKE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
MAX_SUBPROCESS_OUTPUT = 64 * 1024
POOL_CREDENTIAL_KEYS = frozenset(
    {
        "id",
        "label",
        "auth_type",
        "priority",
        "source",
        "access_token",
        "refresh_token",
        "last_refresh",
        "request_count",
        "last_status",
        "last_status_at",
        "last_error_code",
        "last_error_reason",
        "last_error_reset_at",
        "failure_reason",
    }
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def decode_claims(token: str) -> dict[str, Any]:
    try:
        if not isinstance(token, str):
            return {}
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
        return claims if isinstance(claims, dict) else {}
    except (
        IndexError,
        TypeError,
        ValueError,
        UnicodeError,
        binascii.Error,
        json.JSONDecodeError,
    ):
        return {}


def account_header(token: str) -> str | None:
    auth = decode_claims(token).get("https://api.openai.com/auth") or {}
    value = auth.get("chatgpt_account_id") if isinstance(auth, dict) else None
    return value.strip() if isinstance(value, str) and value.strip() else None


def parse_time(value: Any) -> float:
    if isinstance(value, (int, float)):
        try:
            return float(value)
        except (OverflowError, ValueError):
            return 0.0
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return 0.0
    return 0.0


def normalize_reset_at(value: Any) -> int | float | None:
    """Accept only a finite, positive numeric upstream window identifier."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value > 0:
        try:
            float(value)
        except OverflowError:
            return None
        return value
    if isinstance(value, float) and math.isfinite(value) and value > 0:
        return value
    return None


def normalize_used_percent(value: Any) -> float | None:
    """Accept only a finite quota percentage in the provider's valid range."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        normalized = float(value)
    except (OverflowError, ValueError):
        return None
    return normalized if math.isfinite(normalized) and 0 <= normalized <= 100 else None


_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | _NOFOLLOW


def _open_secure_dir(path: Path, *, create: bool) -> int:
    """Open every directory component without following a symlink.

    The returned descriptor anchors all later operations. This avoids a
    path-based check-then-use race when a profile or state directory is
    replaced while the cron process is running.
    """
    if not path.is_absolute() or not path.parts or path.parts[0] != "/":
        raise OSError("secure directory must be an absolute path")
    directory_fd = os.open("/", _DIRECTORY_FLAGS)
    try:
        for component in path.parts[1:]:
            if component in {"", ".", ".."}:
                raise OSError("unsafe directory component")
            try:
                next_fd = os.open(component, _DIRECTORY_FLAGS, dir_fd=directory_fd)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(component, 0o700, dir_fd=directory_fd)
                except FileExistsError:
                    pass
                next_fd = os.open(component, _DIRECTORY_FLAGS, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        return directory_fd
    except Exception:
        os.close(directory_fd)
        raise


def _open_regular(path: Path, flags: int) -> int:
    """Open a regular file below a securely anchored parent directory."""
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise OSError("unsafe file path")
    parent_fd = _open_secure_dir(path.parent, create=False)
    try:
        file_fd = os.open(path.name, flags | _NOFOLLOW, dir_fd=parent_fd)
        try:
            file_stat = os.fstat(file_fd)
            if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_nlink > 1:
                raise OSError("file is not a private regular file")
        except Exception:
            os.close(file_fd)
            raise
        return file_fd
    finally:
        os.close(parent_fd)


def _same_file(first: os.stat_result | None, second: os.stat_result | None) -> bool:
    if first is None or second is None:
        return first is second
    return (
        first.st_dev,
        first.st_ino,
        first.st_uid,
        first.st_gid,
        stat.S_IMODE(first.st_mode),
    ) == (
        second.st_dev,
        second.st_ino,
        second.st_uid,
        second.st_gid,
        stat.S_IMODE(second.st_mode),
    )


def _create_temp(parent_fd: int, prefix: str) -> tuple[int, str]:
    for _ in range(20):
        name = f".{prefix}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
        try:
            file_fd = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW,
                0o600,
                dir_fd=parent_fd,
            )
            return file_fd, name
        except FileExistsError:
            continue
    raise FileExistsError("could not allocate a private temporary file")


def _atomic_replace(
    path: Path,
    contents: str,
    *,
    default_mode: int,
    preserve_existing_mode: bool = False,
    expected_stat: os.stat_result | None = None,
) -> None:
    """Atomically replace a fixed file while preserving its boundary."""
    parent_fd = _open_secure_dir(path.parent, create=True)
    tmp_name: str | None = None
    tmp_fd = -1
    try:
        try:
            existing_stat = os.lstat(path.name, dir_fd=parent_fd)
        except FileNotFoundError:
            existing_stat = None
        if existing_stat is not None and (
            not stat.S_ISREG(existing_stat.st_mode) or existing_stat.st_nlink > 1
        ):
            raise OSError("destination is not a private regular file")
        if expected_stat is not None and not _same_file(existing_stat, expected_stat):
            raise OSError("destination changed during update")

        if existing_stat is None:
            target_mode = default_mode & 0o7777
        elif preserve_existing_mode:
            target_mode = stat.S_IMODE(existing_stat.st_mode)
        else:
            # Never widen an existing destination beyond the requested policy.
            target_mode = stat.S_IMODE(existing_stat.st_mode) & (default_mode & 0o7777)

        tmp_fd, tmp_name = _create_temp(parent_fd, path.name)
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as handle:
            tmp_fd = -1
            handle.write(contents)
            handle.flush()
            os.fchmod(handle.fileno(), target_mode)
            if existing_stat is not None and (
                existing_stat.st_uid != os.geteuid() or existing_stat.st_gid != os.getegid()
            ):
                try:
                    os.fchown(handle.fileno(), existing_stat.st_uid, existing_stat.st_gid)
                except OSError as exc:
                    raise OSError("cannot preserve destination ownership") from exc
            # Metadata changes must be durable before the rename is published.
            os.fsync(handle.fileno())

        try:
            current_stat = os.lstat(path.name, dir_fd=parent_fd)
        except FileNotFoundError:
            current_stat = None
        if not _same_file(current_stat, existing_stat):
            raise OSError("destination changed during update")
        os.replace(tmp_name, path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        if tmp_fd >= 0:
            os.close(tmp_fd)
        if tmp_name is not None:
            try:
                os.unlink(tmp_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        os.close(parent_fd)


def auth_roots() -> list[tuple[str, Path]]:
    """Return only the credential root owned by this rotation job."""
    auth_path = LOCAL_ROOT / "auth.json"
    try:
        file_fd = _open_regular(auth_path, os.O_RDONLY)
        os.close(file_fd)
        return [(LOCAL_PROFILE, LOCAL_ROOT)]
    except OSError:
        return []


def load_json(path: Path) -> dict[str, Any]:
    file_fd = _open_regular(path, os.O_RDONLY)
    try:
        with os.fdopen(file_fd, encoding="utf-8") as handle:
            file_fd = -1
            return json.load(handle)
    finally:
        if file_fd >= 0:
            os.close(file_fd)


def _read_text_with_stat(path: Path) -> tuple[str, os.stat_result]:
    file_fd = _open_regular(path, os.O_RDONLY)
    try:
        file_stat = os.fstat(file_fd)
        with os.fdopen(file_fd, encoding="utf-8") as handle:
            file_fd = -1
            return handle.read(), file_stat
    finally:
        if file_fd >= 0:
            os.close(file_fd)


def fsync_directory(path: Path) -> None:
    """Persist a completed atomic rename."""
    directory_fd = _open_secure_dir(path, create=False)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def atomic_json(path: Path, data: dict[str, Any], mode: int = 0o600) -> None:
    _atomic_replace(path, json.dumps(data, indent=2) + "\n", default_mode=mode)


def append_log(message: str) -> None:
    parent_fd = _open_secure_dir(LOG_PATH.parent, create=True)
    file_fd = -1
    try:
        file_fd = os.open(
            LOG_PATH.name,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND | _NOFOLLOW,
            0o600,
            dir_fd=parent_fd,
        )
        file_stat = os.fstat(file_fd)
        if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_nlink > 1:
            raise OSError("log destination is not a private regular file")
        with os.fdopen(file_fd, "a", encoding="utf-8") as handle:
            file_fd = -1
            handle.write(f"{utc_now()} {message}\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.fsync(parent_fd)
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        os.close(parent_fd)


def open_lock_handle():
    """Open the rotation lock without following or truncating a path."""
    parent_fd = _open_secure_dir(LOCK_PATH.parent, create=True)
    file_fd = -1
    try:
        file_fd = os.open(
            LOCK_PATH.name,
            os.O_RDWR | os.O_CREAT | _NOFOLLOW,
            0o600,
            dir_fd=parent_fd,
        )
        file_stat = os.fstat(file_fd)
        if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_nlink > 1:
            raise OSError("lock destination is not a private regular file")
        handle = os.fdopen(file_fd, "r+", encoding="utf-8")
        file_fd = -1
        return handle
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        os.close(parent_fd)


def seed_credentials() -> dict[str, dict[str, Any]]:
    """Collect the freshest copy of each configured credential."""
    candidates: dict[str, list[dict[str, Any]]] = {label: [] for label in ORDER}
    for _, root in auth_roots():
        try:
            pool = (load_json(root / "auth.json").get("credential_pool") or {}).get("openai-codex") or []
        except (OSError, TypeError, AttributeError, json.JSONDecodeError):
            pool = []
        for credential in pool:
            if not isinstance(credential, dict):
                continue
            label = credential.get("label")
            if label in candidates and isinstance(credential.get("access_token"), str) and credential.get("access_token"):
                candidates[label].append(dict(credential))

    # Do not consult backups or any other profile: they are outside this
    # job's credential boundary and may contain stale or revoked tokens.
    selected: dict[str, dict[str, Any]] = {}
    for label in ORDER:
        if not candidates[label]:
            raise RuntimeError(f"missing OAuth credential: {label}")
        selected[label] = max(
            candidates[label],
            key=lambda c: (parse_time(c.get("last_refresh")), parse_time(c.get("last_status_at"))),
        )
    return selected


def usage_probe(credential: dict[str, Any]) -> dict[str, Any]:
    token = str(credential.get("access_token") or "")
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json", "User-Agent": "codex-cli"}
    account_id = account_header(token)
    if account_id:
        headers["ChatGPT-Account-Id"] = account_id
    request = urllib.request.Request(USAGE_URL, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=15) as response:  # nosec B310 - fixed HTTPS URL
            payload = json.loads(response.read().decode())
        window = ((payload.get("rate_limit") or {}).get("primary_window") or {})
        used_percent = normalize_used_percent(window.get("used_percent"))
        return {
            "ok": used_percent is not None,
            "http": 200,
            "used_percent": used_percent,
            "reset_at": window.get("reset_at"),
            "window_seconds": window.get("limit_window_seconds"),
            "plan": payload.get("plan_type"),
        }
    except urllib.error.HTTPError as exc:
        return {"ok": False, "http": exc.code, "used_percent": None, "reset_at": None}
    except (OSError, TypeError, ValueError, UnicodeError, AttributeError) as exc:
        return {"ok": False, "http": None, "used_percent": None, "reset_at": None, "error": type(exc).__name__}


def clean_credential(credential: dict[str, Any], priority: int, live_ok: bool) -> dict[str, Any]:
    # Round-trip only the minimum OAuth pool schema. In particular, endpoint,
    # client-metadata, agent-key, and secret-fingerprint fields are deliberately
    # excluded: Hermes supplies the fixed provider endpoint and those fields are
    # not required to select or refresh an OpenAI Codex OAuth entry.
    result = {key: credential[key] for key in POOL_CREDENTIAL_KEYS if key in credential}
    result["auth_type"] = "oauth"
    result["priority"] = priority
    if live_ok:
        for key in (
            "last_status", "last_status_at", "last_error_code", "last_error_reason",
            "last_error_message", "last_error_reset_at", "failure_reason",
        ):
            result[key] = None
    return result


def derive_account_state(previous: dict[str, Any], probe: dict[str, Any]) -> dict[str, Any]:
    """Derive a fail-closed per-window state record from one live probe."""
    current_window = normalize_reset_at(probe.get("reset_at"))
    previous_touched = normalize_reset_at(previous.get("touched_reset_at"))
    previous_attempt = normalize_reset_at(previous.get("touch_attempted_reset_at"))
    used = normalize_used_percent(probe.get("used_percent"))
    meter_confirms_use = bool(probe.get("ok") and used is not None and used > 0)

    if current_window is None:
        status = "window_unknown"
        touched = False
        touched_reset_at = previous_touched
        attempted_reset_at = previous_attempt
    elif probe.get("ok") and (meter_confirms_use or previous_touched == current_window):
        status = "confirmed"
        touched = True
        touched_reset_at = current_window
        attempted_reset_at = current_window if previous_attempt == current_window else None
    elif previous_attempt == current_window:
        # A prompt may have reached the provider even when the local process
        # crashed or timed out. Never retry that window.
        status = "ambiguous"
        touched = False
        touched_reset_at = None
        attempted_reset_at = current_window
    else:
        status = "untouched"
        touched = False
        touched_reset_at = None
        attempted_reset_at = None

    return {
        "reset_at": current_window,
        "used_percent": used,
        "touched": touched,
        "touched_reset_at": touched_reset_at,
        "touch_attempted_reset_at": attempted_reset_at,
        "touch_status": status,
        "http": probe.get("http"),
        "checked_at": utc_now(),
    }


def synchronize_pools(credentials: dict[str, dict[str, Any]], probes: dict[str, dict[str, Any]], target: str) -> list[str]:
    """Keep this profile's pool ordered around the selected target.

    Credential stores are intentionally not synchronized across profiles.
    """
    changed: list[str] = []
    for name, root in auth_roots():
        ordered = [target] + [label for label in ORDER if label != target]
        pool = [clean_credential(credentials[label], index, bool(probes[label].get("ok"))) for index, label in enumerate(ordered)]
        path = root / "auth.json"
        data = load_json(path)
        raw_pool = (data.get("credential_pool") or {}).get("openai-codex") or []
        old_pool = raw_pool if isinstance(raw_pool, list) else []
        # Compare the complete sanitized rows, not only labels/tokens. This
        # forces a rewrite when a stale or hostile row contains endpoint,
        # authentication-metadata, or otherwise unrecognized fields.
        if old_pool == pool:
            continue
        data.setdefault("credential_pool", {})["openai-codex"] = pool
        data.setdefault("providers", {})["openai-codex"] = {}
        data["updated_at"] = utc_now()
        atomic_json(path, data)
        changed.append(name)
    return changed


def load_state() -> dict[str, Any]:
    try:
        value = load_json(STATE_PATH)
        return value if isinstance(value, dict) else {}
    except (FileNotFoundError, PermissionError, json.JSONDecodeError):
        return {"version": 1, "accounts": {}, "active": None}


def sanitize_state(raw: Any) -> dict[str, Any]:
    """Keep only the bounded rotation state schema before rewriting it."""
    raw = raw if isinstance(raw, dict) else {}
    raw_accounts = raw.get("accounts") if isinstance(raw.get("accounts"), dict) else {}
    active = raw.get("active") if raw.get("active") in ORDER else None
    clean: dict[str, Any] = {"version": 1, "accounts": {}, "active": active}
    if isinstance(raw.get("all_touched"), bool):
        clean["all_touched"] = raw["all_touched"]
    if raw.get("reconciliation_pending") is True:
        clean["reconciliation_pending"] = True
        target = raw.get("reconciliation_target")
        clean["reconciliation_target"] = target if target in ORDER else None
    for label in ORDER:
        previous = raw_accounts.get(label)
        if not isinstance(previous, dict):
            previous = {}
        clean["accounts"][label] = {
            key: previous[key]
            for key in ("reset_at", "touched_reset_at", "touch_attempted_reset_at")
            if key in previous
        }
    return clean


def save_state(state: dict[str, Any]) -> None:
    state["updated_at"] = utc_now()
    atomic_json(STATE_PATH, state)


def write_usage_cache(credentials: dict[str, dict[str, Any]], probes: dict[str, dict[str, Any]], target: str) -> bool:
    """Publish a profile-local usage snapshot for the status plugin and banners."""
    accounts: dict[str, dict[str, Any]] = {}
    for label in ORDER:
        probe = probes[label]
        reset_at = normalize_reset_at(probe.get("reset_at"))
        used_percent = normalize_used_percent(probe.get("used_percent"))
        entry: dict[str, Any] = {
            "used_percent": used_percent,
            "http": probe.get("http"),
            "ok": bool(probe.get("ok")) and used_percent is not None,
            "checked_at": utc_now(),
        }
        if reset_at is not None:
            entry["reset_epoch"] = float(reset_at)
        accounts[label] = entry
    payload = {
        "version": 1,
        "active": target,
        "accounts": accounts,
        "updated_at": utc_now(),
    }
    try:
        atomic_json(PROFILE_USAGE_CACHE, payload, mode=0o644)
    except (OSError, TypeError, ValueError) as exc:
        append_log(f"usage-cache error {type(exc).__name__}: {exc}")
        return False
    try:
        refresh_agents_blocks(payload)
    except Exception as exc:  # noqa: BLE001 - optional publication boundary
        append_log(f"usage-cache annotation error {type(exc).__name__}: {exc}")
        return False
    return True


BEGIN_MARK = "<!-- codex-usage:auto BEGIN -->"
END_MARK = "<!-- codex-usage:auto END -->"


def refresh_agents_blocks(payload: dict[str, Any]) -> None:
    """Stamp the usage snapshot into this profile's AGENTS.md."""
    short = {
        "tabiaadib": "tabiaadib",
        "smaadibusa": "smaadibusa",
        "aadibsmusa1": "aadibsmusa1",
    }
    lines = ["## Codex account usage", ""]
    for label, name in short.items():
        acct = payload.get("accounts", {}).get(label) or {}
        used = normalize_used_percent(acct.get("used_percent"))
        state = status_word(used, bool(acct.get("ok")))
        pct = f"{used:.0f}%" if used is not None else "?"
        lines.append(f"- {name}: {pct} used ({state}); resets in {fmt_reset_short(acct.get('reset_epoch'))}")
    active = short.get(payload.get("active"), payload.get("active") or "?")
    lines.append(f"- Active credential: {active} (hourly auto-refresh)")
    block = f"{BEGIN_MARK}\n{chr(10).join(lines)}\n{END_MARK}"

    path = LOCAL_ROOT / "AGENTS.md"
    try:
        # AGENTS.md is shared fleet context and may be owned by `hermes`.
        # Read through a securely anchored descriptor, then publish a complete
        # replacement while preserving its existing ownership and mode.
        existing, existing_stat = _read_text_with_stat(path)
        if BEGIN_MARK in existing and END_MARK in existing:
            pre = existing.split(BEGIN_MARK)[0]
            post = existing.split(END_MARK)[1]
            updated = pre + block + post
        elif existing.strip():
            updated = existing.rstrip() + "\n\n" + block + "\n"
        else:
            return  # don't create AGENTS.md where none was intended
        if updated != existing:
            _atomic_replace(
                path,
                updated,
                default_mode=0o644,
                preserve_existing_mode=True,
                expected_stat=existing_stat,
            )
    except FileNotFoundError:
        return
    except (OSError, UnicodeError) as exc:
        append_log(f"agents-block error {LOCAL_PROFILE}: {type(exc).__name__}: {exc}")


def status_word(used: float | None, ok: bool) -> str:
    used = normalize_used_percent(used)
    if not ok:
        return "unreachable"
    if used is None:
        return "unknown"
    if used >= 100:
        return "FULL"
    if used >= 80:
        return "high"
    return "OK"


def fmt_reset_short(epoch: Any) -> str:
    epoch = normalize_reset_at(epoch)
    if epoch is None:
        return "?"
    delta = epoch - time.time()
    if delta <= 0:
        return "now"
    return f"{delta / 3600:.1f}h" if delta >= 3600 else f"{delta / 60:.0f}m"


def _run_bounded(
    command: list[str],
    *,
    timeout: float,
    cwd: str,
    env: dict[str, str],
) -> tuple[int, str, str, str | None]:
    """Run fixed argv with bounded stdout/stderr and no inherited input."""
    process = subprocess.Popen(  # nosec B603 - fixed argv, shell disabled
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        cwd=cwd,
        env=dict(env),
        shell=False,
        close_fds=True,
    )
    selector = selectors.DefaultSelector()
    streams = {
        "stdout": process.stdout,
        "stderr": process.stderr,
    }
    for name, stream in streams.items():
        if stream is not None:
            selector.register(stream, selectors.EVENT_READ, name)
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    reason: str | None = None
    try:
        deadline = time.monotonic() + timeout
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                reason = "timeout"
                process.kill()
                break
            events = selector.select(remaining)
            if not events:
                reason = "timeout"
                process.kill()
                break
            stop = False
            for key, _ in events:
                try:
                    chunk = os.read(key.fileobj.fileno(), 8192)
                except OSError:
                    chunk = b""
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                buffer = buffers[key.data]
                room = MAX_SUBPROCESS_OUTPUT - len(buffer)
                if room <= 0 or len(chunk) > room:
                    if room > 0:
                        buffer.extend(chunk[:room])
                    reason = "output_limit"
                    process.kill()
                    stop = True
                    break
                buffer.extend(chunk)
            if stop:
                break
        if reason:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        else:
            process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        reason = "timeout"
        process.kill()
        process.wait()
    finally:
        selector.close()
        for stream in streams.values():
            if stream is not None:
                stream.close()
    returncode = process.returncode if process.returncode is not None else 124
    if reason:
        buffers["stdout"].clear()
        buffers["stderr"].clear()
    stdout = bytes(buffers["stdout"]).decode("utf-8", "replace")
    stderr = bytes(buffers["stderr"]).decode("utf-8", "replace")
    return returncode, stdout, stderr, reason


def run_smoke() -> tuple[bool, str]:
    command = [
        str(HERMES_BIN), "chat", "-p", SMOKE_PROFILE,
        "-q", "Reply with exactly: ROTATION_OK", "-Q",
    ]
    # The Hermes CLI resolves this profile from HOME; no provider, transport,
    # or caller environment variables are allowed across the subprocess edge.
    env = {"HOME": "/home/hermes", "PATH": SMOKE_PATH}
    try:
        returncode, stdout, _stderr, reason = _run_bounded(
            command,
            timeout=180,
            cwd="/home/hermes",
            env=env,
        )
    except OSError:
        return False, "spawn_error"
    if reason:
        return False, reason
    stdout_text = stdout.strip()
    return returncode == 0 and stdout_text == "ROTATION_OK", f"exit={returncode}"


def reconcile_outputs(
    credentials: dict[str, dict[str, Any]],
    probes: dict[str, dict[str, Any]],
    target: str,
) -> tuple[list[str], list[str]]:
    """Publish pool/cache independently and report a retryable failure marker."""
    try:
        changed = synchronize_pools(credentials, probes, target)
    except Exception as exc:  # noqa: BLE001 - publication boundary is fail-closed
        append_log(f"pool publication error {type(exc).__name__}")
        return [], ["pool"]
    try:
        cache_ok = write_usage_cache(credentials, probes, target)
    except Exception as exc:  # noqa: BLE001 - publication boundary is fail-closed
        append_log(f"usage-cache publication error {type(exc).__name__}")
        return changed, ["usage-cache"]
    if cache_ok is False:
        return changed, ["usage-cache"]
    return changed, []


def set_reconciliation_marker(state: dict[str, Any], target: str, errors: list[str]) -> None:
    """Durably describe incomplete secondary publication without raw errors."""
    if errors:
        state["reconciliation_pending"] = True
        state["reconciliation_target"] = target if target in ORDER else None
    else:
        state.pop("reconciliation_pending", None)
        state.pop("reconciliation_target", None)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", action="store_true")
    parser.add_argument("--no-smoke", action="store_true")
    args = parser.parse_args()

    with open_lock_handle() as lock_handle:
        try:
            fcntl.flock(lock_handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return 0

        try:
            credentials = seed_credentials()
            probes = {label: usage_probe(credentials[label]) for label in ORDER}
            state = sanitize_state(load_state())
            account_state = state.setdefault("accounts", {})
            for label in ORDER:
                probe = probes[label]
                previous = account_state.get(label) or {}
                current_window = normalize_reset_at(probe.get("reset_at"))
                if current_window is not None and normalize_reset_at(previous.get("reset_at")) != current_window:
                    append_log(f"new usage window label={label} reset_at={current_window}")
                account_state[label] = derive_account_state(previous, probe)

            unavailable = [label for label in ORDER if not probes[label].get("ok")]
            unknown_windows = [
                label for label in ORDER
                if probes[label].get("ok") and account_state[label]["reset_at"] is None
            ]
            ambiguous = [
                label for label in ORDER
                if account_state[label].get("touch_status") == "ambiguous"
            ]
            pending = [
                label for label in ORDER
                if probes[label].get("ok")
                and account_state[label]["reset_at"] is not None
                and account_state[label].get("touch_status") == "untouched"
            ]
            retry_target = state.get("reconciliation_target")
            target = (
                pending[0]
                if pending
                else retry_target
                if state.get("reconciliation_pending") and retry_target in ORDER
                else PREFERRED
            )
            changed, publication_errors = reconcile_outputs(credentials, probes, target)
            if state.get("active") != target:
                append_log(f"active credential changed from={state.get('active')} to={target}")
            state["active"] = target
            state["all_touched"] = not pending and not unavailable and not unknown_windows and not ambiguous
            state.pop("all_seeded", None)
            set_reconciliation_marker(state, target, publication_errors)
            save_state(state)

            if publication_errors:
                print("⚠️ Codex rotation publication is pending; no smoke prompt sent")
                return 1

            smoke_result = None
            blockers = unavailable + unknown_windows + ambiguous
            if blockers:
                details = []
                if unavailable:
                    details.append(
                        "unavailable="
                        + ",".join(f"{label}:HTTP {probes[label].get('http')}" for label in unavailable)
                    )
                if unknown_windows:
                    details.append("window_unknown=" + ",".join(unknown_windows))
                if ambiguous:
                    details.append("touch_ambiguous=" + ",".join(ambiguous))
                print("⚠️ Codex rotation blocked: " + "; ".join(details))
                return 1

            if pending and target == pending[0] and not args.no_smoke:
                touch_window = account_state[target].get("reset_at")
                if normalize_reset_at(touch_window) is None:
                    print(f"⚠️ Codex rotation blocked: window_unknown={target}")
                    return 1

                # Persist before the request. A timeout, crash, or ambiguous
                # subprocess result must never cause a second prompt in this
                # upstream window.
                account_state[target]["touch_attempted_reset_at"] = touch_window
                account_state[target]["touch_status"] = "ambiguous"
                account_state[target]["touched"] = False
                account_state[target]["touched_reset_at"] = None
                state["all_touched"] = False
                save_state(state)

                try:
                    ok, detail = run_smoke()
                except (OSError, subprocess.TimeoutExpired) as exc:
                    ok, detail = False, type(exc).__name__
                smoke_result = ok
                append_log(f"smoke label={target} ok={ok} {detail}")
                if not ok:
                    account_state[target]["touch_status"] = "ambiguous"
                    account_state[target]["touch_error"] = "provider_result_unknown"
                    save_state(state)
                    print(f"⚠️ Codex rotation smoke failed or was ambiguous for {target}: {detail}")
                    return 1

                # A successful inference is the signal we need. Re-probe only
                # to capture the authoritative window id; the displayed usage
                # may legitimately remain rounded to 0%.
                post_probe = usage_probe(credentials[target])
                post_window = normalize_reset_at(post_probe.get("reset_at"))
                if not post_probe.get("ok") or post_window is None:
                    account_state[target]["touch_status"] = "ambiguous"
                    account_state[target]["touch_error"] = "post_probe_unknown"
                    save_state(state)
                    print(f"⚠️ Codex rotation smoke result could not be verified for {target}")
                    return 1
                probes[target] = post_probe
                if post_window != touch_window:
                    # The request crossed a quota-window boundary. It counted
                    # for the old window, while the new one remains untouched;
                    # do not send a second prompt in this tick.
                    account_state[target]["reset_at"] = post_window
                    account_state[target]["used_percent"] = post_probe.get("used_percent")
                    account_state[target]["http"] = post_probe.get("http")
                    account_state[target]["touched"] = False
                    account_state[target]["touched_reset_at"] = touch_window
                    account_state[target]["touch_status"] = "untouched"
                    window_changed = True
                else:
                    account_state[target]["touched"] = True
                    account_state[target]["touched_reset_at"] = touch_window
                    account_state[target]["touch_status"] = "confirmed"
                    account_state[target].pop("touch_error", None)
                    window_changed = False
                # Make the post-request decision durable before any later
                # pool/cache write can fail or the process can exit.
                save_state(state)

                remaining = [label for label in pending if label != target]
                final_target = remaining[0] if remaining else PREFERRED
                more_changes, publication_errors = reconcile_outputs(credentials, probes, final_target)
                changed.extend(name for name in more_changes if name not in changed)
                state["active"] = final_target
                state["all_touched"] = not remaining and not unavailable and not unknown_windows and not ambiguous and not window_changed
                set_reconciliation_marker(state, final_target, publication_errors)
                save_state(state)
                target = final_target
                if publication_errors:
                    print("⚠️ Codex rotation publication is pending after smoke; no retry will be sent")
                    return 1

            if args.report:
                summary = {
                    "scope": LOCAL_PROFILE,
                    "pool_labels": ORDER,
                    "oauth1_slot": OAUTH1,
                    "preferred_slot": PREFERRED,
                    "active": target,
                    "usage": {label: probes[label].get("used_percent") for label in ORDER},
                    "touched_this_window": {label: account_state[label]["touched"] for label in ORDER},
                    "all_touched": state["all_touched"],
                    "profiles_updated": changed,
                    "smoke_sent": smoke_result,
                    "credential_copy": "none across profiles (local pool only)",
                    "policy": "exactly one successful minimal prompt per credential per usage window; no 1% target",
                }
                print(json.dumps(summary, indent=2))
            return 0
        except Exception as exc:  # noqa: BLE001 - top-level cron boundary is fail-closed
            append_log(f"error {type(exc).__name__}: {exc}")
            print(f"⚠️ Codex rotation error: {type(exc).__name__}: {exc}")
            return 1


if __name__ == "__main__":
    sys.exit(main())
