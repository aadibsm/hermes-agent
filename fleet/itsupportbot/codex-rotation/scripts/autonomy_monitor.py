#!/usr/bin/env python3
"""Zero-LLM change detector for itsupportbot autonomy heartbeat.

Output contract (hermes-autonomy monitor mode):
  - "UNCHANGED"            -> nothing to do, cron stays silent (no LLM spend)
  - "CHANGED: <details>"   -> agent run triggered with this diff injected

Stability rules: NO timestamps, NO volatile counters (usage-window resets,
checked_at). Only durable facts: error states, process liveness, threshold
crossings. Sorted deterministically.
"""
from __future__ import annotations

import json
import math
import os
import selectors

# Fixed local probes only; shell execution is never used.
import subprocess  # nosec B404 - fixed local probe commands only
import time
import urllib.error
import urllib.request
from pathlib import Path

ROTATION_STATE = Path("/home/hermes/.hermes/profiles/itsupportbot/state/codex-account-rotation.json")
WATCHDOG_STATE = Path("/home/hermes/.local/state/hermes-stack-watchdog/state.json")
HEALTH_URL = "http://192.168.4.24:8787/health"
SYSTEMCTL_BIN = "/usr/bin/systemctl"
PGREP_BIN = "/usr/bin/pgrep"
DF_BIN = "/usr/bin/df"
SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
SAFE_ENV = {
    "HOME": "/home/hermes",
    "PATH": SAFE_PATH,
    "LANG": "C",
    "LC_ALL": "C",
}
MAX_HELPER_OUTPUT = 64 * 1024
DISK_STEP = 5          # report only in 5% bands to avoid churn
USAGE_WARN = 80        # percent


def _finite_percent(value) -> bool:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False
    try:
        normalized = float(value)
    except (OverflowError, ValueError):
        return False
    return math.isfinite(normalized) and 0 <= normalized <= 100


CODEX_ACCOUNTS = (
    "tabiaadib",
    "smaadibusa",
    "aadibsmusa1",
)
PROFILE_GATEWAYS = {
    "aadibassistant",
    "deal-agent",
    "job-agent",
    "securityplus-coach",
    "stock-agent",
}


def sh(argv: list[str]) -> str | None:
    try:
        process = subprocess.Popen(  # nosec B603 - fixed executable and argv
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            shell=False,
            close_fds=True,
            cwd="/home/hermes",
            env=dict(SAFE_ENV),
        )
    except OSError:
        return None
    selector = selectors.DefaultSelector()
    streams = {"stdout": process.stdout, "stderr": process.stderr}
    for name, stream in streams.items():
        if stream is not None:
            selector.register(stream, selectors.EVENT_READ, name)
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    unavailable = False
    try:
        deadline = time.monotonic() + 20
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                unavailable = True
                process.kill()
                break
            events = selector.select(remaining)
            if not events:
                unavailable = True
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
                room = MAX_HELPER_OUTPUT - len(buffer)
                if room <= 0 or len(chunk) > room:
                    if room > 0:
                        buffer.extend(chunk[:room])
                    unavailable = True
                    process.kill()
                    stop = True
                    break
                buffer.extend(chunk)
            if stop:
                break
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            unavailable = True
            process.kill()
            process.wait()
    except (OSError, subprocess.TimeoutExpired):
        unavailable = True
        try:
            process.kill()
            process.wait()
        except OSError:
            pass
    finally:
        selector.close()
        for stream in streams.values():
            if stream is not None:
                stream.close()
    if unavailable:
        return None
    return bytes(buffers["stdout"]).decode("utf-8", "replace").strip()


def read_json_if_accessible(path: Path) -> dict | None:
    """Read an aggregate state file only when directly accessible.

    This monitor is intentionally unprivileged; it must not turn a missing
    read ACL into a sudo/root execution path. Callers receive ``None`` and
    emit a stable unavailable signal instead.
    """
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else None
    except (OSError, ValueError):
        return None


def codex_signals() -> list[str]:
    out: list[str] = []
    data = read_json_if_accessible(ROTATION_STATE)
    if data is None:
        return ["codex: rotation state unreadable"]
    accounts = data.get("accounts")
    if not isinstance(accounts, dict):
        return ["codex: rotation state unreadable"]
    recognized = {
        label: info
        for label in CODEX_ACCOUNTS
        if isinstance((info := accounts.get(label)), dict)
    }
    missing_count = len(CODEX_ACCOUNTS) - len(recognized)
    if missing_count:
        out.append(f"codex.missing_account_count={missing_count}")
    unknown_count = sum(label not in CODEX_ACCOUNTS for label in accounts)
    if unknown_count:
        out.append(f"codex.unrecognized_account_count={unknown_count}")

    # NOTE: codex.active intentionally excluded — it rotates routinely by
    # design; only anomaly signals belong in the change fingerprint.
    if data.get("all_touched") is False and data.get("active") in CODEX_ACCOUNTS:
        ambiguous = [
            label for label in CODEX_ACCOUNTS
            if label in recognized and recognized[label].get("touch_status") == "ambiguous"
        ]
        if ambiguous:
            out.append(f"codex.touch_ambiguous={','.join(ambiguous)}")
        unknown_windows = [
            label for label in CODEX_ACCOUNTS
            if label in recognized and recognized[label].get("touch_status") == "window_unknown"
        ]
        if unknown_windows:
            out.append(f"codex.window_unknown={','.join(unknown_windows)}")
        pending = [
            label for label in CODEX_ACCOUNTS
            if label in recognized
            and not recognized[label].get("touched")
            and recognized[label].get("touch_status") not in {"ambiguous", "window_unknown"}
        ]
        if pending:
            out.append(f"codex.pending_windows={','.join(pending)}")
    for label in CODEX_ACCOUNTS:
        info = recognized.get(label)
        if info is None:
            continue
        http = info.get("http")
        if isinstance(http, int) and http != 200:
            out.append(f"codex.error={label}:http{http if 100 <= http <= 599 else 'unknown'}")
        elif http is not None and not isinstance(http, int):
            out.append(f"codex.error={label}:http_unknown")
        used = info.get("used_percent")
        if _finite_percent(used) and used >= USAGE_WARN:
            band = int(used // 10) * 10
            out.append(f"codex.usage_band={label}:{band}+")
    return out


def gateway_signals() -> list[str]:
    names: set[str] = set()
    probe_unavailable = False
    system_gateways = {
        "default": "hermes-gateway.service",
        "itsupportbot": "hermes-gateway-itsupportbot.service",
    }
    for label, unit in system_gateways.items():
        state = sh([SYSTEMCTL_BIN, "is-active", unit])
        if state is None:
            probe_unavailable = True
        elif state == "active":
            names.add(label)

    procs = sh([PGREP_BIN, "-af", "hermes_cli.main.*gateway run"])
    unrecognized_count = 0
    malformed_count = 0
    if procs is None:
        probe_unavailable = True
    else:
        for line in procs.splitlines():
            parts = line.split()
            profile = None
            for index, token in enumerate(parts):
                if token == "--profile":  # nosec B105 - CLI option, not a credential
                    if index + 1 >= len(parts):
                        malformed_count += 1
                    else:
                        profile = parts[index + 1]
                    break
                if token.startswith("--profile="):
                    profile = token.partition("=")[2]
                    if not profile:
                        malformed_count += 1
                    break
            if profile is not None:
                if profile in PROFILE_GATEWAYS:
                    names.add(profile)
                else:
                    unrecognized_count += 1
    output = ["gateways.up=" + ",".join(sorted(names))]
    if probe_unavailable:
        output.append("gateways.probe_unavailable=true")
    if unrecognized_count:
        output.append(f"gateways.unrecognized_count={unrecognized_count}")
    if malformed_count:
        output.append(f"gateways.malformed_process_count={malformed_count}")
    return output


def watchdog_signals() -> list[str]:
    data = read_json_if_accessible(WATCHDOG_STATE)
    if data is None:
        return ["watchdog.state_unreadable"]
    return ["watchdog.degraded=true"] if data.get("issues") else ["watchdog.all_ok"]


def systemd_signals() -> list[str]:
    units = sh([SYSTEMCTL_BIN, "list-units", "--failed", "--plain", "--no-legend"])
    if units is None:
        return ["systemd.failed_units=unknown"]
    failed = sorted(line.split()[0] for line in units.splitlines() if line.strip())
    if failed:
        return [f"systemd.failed_count={len(failed)}"]
    return ["systemd.failed_units=none"]


def disk_signals() -> list[str]:
    raw = sh([DF_BIN, "--output=pcent", "/"])
    if raw is None:
        return ["disk.root=unknown"]
    line = raw.splitlines()
    try:
        pct = int(line[-1].strip().rstrip("%"))
    except (IndexError, ValueError):
        return ["disk.root=unknown"]
    return [f"disk.root_band={pct // DISK_STEP * DISK_STEP}+"]


def health_signals() -> list[str]:
    try:
        # HEALTH_URL is a fixed local health endpoint.
        with urllib.request.urlopen(HEALTH_URL, timeout=5) as response:  # nosec B310
            data = json.load(response)
        if not isinstance(data, dict):
            raise TypeError("invalid health payload")
        flags = {k: bool(data.get(k)) for k in ("ok", "whatsapp", "model", "queue")}
    except (OSError, TypeError, ValueError, urllib.error.URLError):
        return ["healthbot.unreachable=true"]
    bad = sorted(k for k, v in flags.items() if not v)
    return [f"healthbot.degraded={','.join(bad)}"] if bad else ["healthbot.all_ok"]


def main() -> None:
    signals: list[str] = []
    signals += codex_signals()
    signals += gateway_signals()
    signals += watchdog_signals()
    signals += systemd_signals()
    signals += disk_signals()
    signals += health_signals()
    fingerprint = "\n".join(sorted(signals))
    print(f"FINGERPRINT\n{fingerprint}", end="")


if __name__ == "__main__":
    main()
