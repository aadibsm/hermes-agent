# ruff: noqa: N999
"""Zero-token IT support status slash commands.

Reads the world-readable snapshot written hourly by the Codex OAuth
rotation (state/codex-usage.json) and renders it as a Telegram-friendly
message. Additional handlers expose bounded local fleet, cron, usage, and
autonomy summaries without invoking an LLM.
"""
from __future__ import annotations

import json
import math
import os
import selectors
import shutil

# Fixed local status commands only; shell execution is never used.
import subprocess  # nosec B404 - fixed profile-local status helpers only
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import yaml

USAGE_CACHE = Path("/home/hermes/.hermes/profiles/itsupportbot/state/codex-usage.json")
PROFILE_HOME = Path("/home/hermes/.hermes/profiles/itsupportbot")
CONFIG_FILE = PROFILE_HOME / "config.yaml"
JOBS_FILE = PROFILE_HOME / "cron" / "jobs.json"
AUTONOMY_MEMORY = PROFILE_HOME / "state" / "autonomy-memory"
AUTONOMY_BOARD = PROFILE_HOME / "state" / "autonomy-kanban" / "board.json"
BURN_HELPER = PROFILE_HOME / "scripts" / "itstatus_burn.py"
PYTHON_BIN = "/home/hermes/.hermes/hermes-agent/venv/bin/python3"
WATCHDOG_STATE = Path("/home/hermes/.local/state/hermes-stack-watchdog/state.json")
HEALTHBOT_URL = "http://192.168.4.24:8787/health"
ITSUPPORT_GATEWAY = "hermes-gateway-itsupportbot.service"
SYSTEMCTL_BIN = "/usr/bin/systemctl"
SAFE_AUTONOMY_MODES = {"monitor-only-v1", "repair-enabled-v1"}
SAFE_JOB_LABELS = {
    "d3d1e28e642e": "Codex quota watchdog",
    "e0da768bb1ac": "Family PA daily steward",
    "32ecdafaf92c": "Weekly deep fleet audit",
    "6b61dc226da2": "Hourly Codex account rotation",
    "e7b1f895686e": "Weekly fleet-wide Hermes update",
    "990def203ebc": "Autonomy heartbeat",
}
BURN_METRICS = {
    "total_sessions",
    "total_messages",
    "total_input_tokens",
    "total_output_tokens",
    "total_cache_read_tokens",
    "total_cache_write_tokens",
    "total_tokens",
}
SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
SAFE_ENV = {
    "HOME": "/home/hermes",
    "PATH": SAFE_PATH,
    "LANG": "C",
    "LC_ALL": "C",
    "PYTHONNOUSERSITE": "1",
}
MAX_HELPER_OUTPUT = 64 * 1024

LABELS = {
    "tabiaadib": "tabiaadib",
    "smaadibusa": "smaadibusa",
    "aadibsmusa1": "aadibsmusa1",
}

_BAR_WIDTH = 10


def _finite_number(value) -> bool:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False
    try:
        return math.isfinite(value)
    except (OverflowError, ValueError):
        return False


def _bar(used) -> str:
    if not _finite_number(used):
        return "?" * _BAR_WIDTH
    filled = round(max(0.0, min(100.0, used)) / 100 * _BAR_WIDTH)
    return "#" * filled + "." * (_BAR_WIDTH - filled)


def _fmt_reset(reset_epoch) -> str:
    if not _finite_number(reset_epoch) or reset_epoch <= 0:
        return "reset unknown"
    hours = max(0.0, reset_epoch - time.time()) / 3600.0
    if hours < 1:
        return f"resets in {max(1, int(hours * 60))}m"
    return f"resets in {hours:.1f}h"


def handle_codex(raw_args: str):
    raw_args = (raw_args or "").strip().lower()
    if raw_args == "json":
        return "Raw JSON output is disabled for privacy."
    try:
        payload = json.loads(USAGE_CACHE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return "No usage cache yet — the hourly rotation has not run on this host."
    except (OSError, UnicodeError, ValueError):
        return "Could not read usage cache safely."

    if not isinstance(payload, dict):
        return "Usage cache is unavailable."
    accounts = payload.get("accounts")
    if not isinstance(accounts, dict):
        return "Usage cache is unavailable."
    if not accounts:
        return "Usage cache is empty."

    lines = ["*Codex account pool*", ""]
    for key, label in LABELS.items():
        acct = accounts.get(key)
        if not isinstance(acct, dict):
            acct = {}
        used = acct.get("used_percent")
        pct = f"{used:.0f}%" if _finite_number(used) else "?"
        if not _finite_number(used):
            state = "?"
        elif not acct.get("ok"):
            state = "unreachable"
        elif used >= 100:
            state = "FULL"
        elif used >= 80:
            state = "high"
        else:
            state = "OK"
        marker = " ◀" if payload.get("active") == key else ""
        lines.append(f"`{label}`")
        lines.append(f"{_bar(used)} {pct} {state}{marker}")
        lines.append(f"_{_fmt_reset(acct.get('reset_epoch'))}_")
        lines.append("")

    updated = payload.get("updated_at")
    updated_text = "unknown"
    if isinstance(updated, str):
        try:
            updated_text = datetime.fromisoformat(updated.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M UTC")
        except ValueError:
            pass
    lines.append(f"_updated: {updated_text}_")
    lines.append("_source: hourly codex-account-rotation cron_")
    return "\n".join(lines)


def _run_bounded(argv: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
    """Run a fixed local helper with bounded stdout/stderr and clean env."""
    try:
        process = subprocess.Popen(  # nosec B603 - fixed executable and argv
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            shell=False,
            close_fds=True,
            cwd=str(PROFILE_HOME),
            env=dict(SAFE_ENV),
        )
    except OSError as exc:
        return subprocess.CompletedProcess(argv, 124, "", type(exc).__name__)
    selector = selectors.DefaultSelector()
    streams = {"stdout": process.stdout, "stderr": process.stderr}
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
                room = MAX_HELPER_OUTPUT - len(buffer)
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
    if reason:
        buffers["stdout"].clear()
        buffers["stderr"].clear()
    stdout = bytes(buffers["stdout"]).decode("utf-8", "replace")
    stderr = bytes(buffers["stderr"]).decode("utf-8", "replace")
    return subprocess.CompletedProcess(
        argv,
        process.returncode if process.returncode is not None else 124,
        stdout,
        reason or stderr,
    )


def _run(argv: list[str], timeout: int = 10) -> subprocess.CompletedProcess[str]:
    return _run_bounded(argv, timeout)


def _read_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def _load_config() -> dict:
    try:
        value = yaml.safe_load(CONFIG_FILE.read_text(encoding="utf-8")) or {}
        return value if isinstance(value, dict) else {}
    except (OSError, yaml.YAMLError):
        return {}


def _service_snapshot() -> dict:
    state = _run([SYSTEMCTL_BIN, "is-active", ITSUPPORT_GATEWAY], timeout=5).stdout.strip()
    if state not in {"active", "inactive", "failed", "activating", "deactivating"}:
        state = "unknown"
    result = _run(
        [
            SYSTEMCTL_BIN,
            "show",
            ITSUPPORT_GATEWAY,
            "-p",
            "NRestarts",
            "-p",
            "MemoryCurrent",
            "--no-pager",
        ],
        timeout=5,
    )
    props = {}
    for line in result.stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            props[key] = value

    def as_int(value: str | None) -> int:
        try:
            return int(value or 0)
        except ValueError:
            return 0

    return {
        "state": state or "unknown",
        "restarts": as_int(props.get("NRestarts")),
        "memory_bytes": as_int(props.get("MemoryCurrent")),
    }


def _host_snapshot() -> dict:
    try:
        disk = shutil.disk_usage("/")
        disk_pct = round(disk.used * 100 / disk.total) if disk.total else 0
    except OSError:
        disk_pct = 0
    meminfo = {}
    try:
        for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
            if ":" in line:
                key, rest = line.split(":", 1)
                meminfo[key] = int(rest.strip().split()[0])
    except (OSError, ValueError, IndexError):
        pass
    total = meminfo.get("MemTotal", 0)
    available = meminfo.get("MemAvailable", 0)
    memory_pct = round((total - available) * 100 / total) if total else 0
    return {"disk_pct": disk_pct, "memory_pct": memory_pct}


def _watchdog_snapshot() -> dict:
    payload = _read_json(WATCHDOG_STATE)
    issues = payload.get("issues") if isinstance(payload.get("issues"), list) else []
    readable = bool(payload)
    return {"ok": readable and not issues, "issue_count": len(issues), "readable": readable}


def _healthbot_state() -> str:
    try:
        # HEALTHBOT_URL is a fixed local health endpoint.
        with urllib.request.urlopen(HEALTHBOT_URL, timeout=3) as response:  # nosec B310
            payload = json.load(response)
        if not isinstance(payload, dict):
            raise TypeError("invalid health payload")
        healthy = response.status == 200 and all(
            payload.get(key) for key in ("ok", "whatsapp", "model", "queue")
        )
        return "healthy" if healthy else "degraded"
    except (OSError, TypeError, ValueError, urllib.error.URLError):
        return "unreachable from Hermes"


def _jobs() -> list[dict]:
    payload = _read_json(JOBS_FILE)
    jobs = payload.get("jobs") if isinstance(payload.get("jobs"), list) else []
    return [job for job in jobs if isinstance(job, dict)]


def _jobs_summary() -> dict:
    jobs = _jobs()
    enabled = [job for job in jobs if job.get("enabled")]
    return {
        "total": len(jobs),
        "enabled": len(enabled),
        "errors": sum(job.get("last_status") == "error" for job in enabled),
        "pending": sum(job.get("last_status") is None for job in enabled),
    }


def _itstatus_snapshot() -> dict:
    config = _load_config()
    model = config.get("model") if isinstance(config.get("model"), dict) else {}
    agent = config.get("agent") if isinstance(config.get("agent"), dict) else {}
    fallbacks = config.get("fallback_providers")
    fallback_enabled = isinstance(fallbacks, list) and bool(fallbacks)

    def allow(value, choices: set[str]) -> str:
        return value if isinstance(value, str) and value in choices else "unknown/untrusted"

    return {
        "gateway": _service_snapshot(),
        "model": {
            "provider": allow(model.get("provider"), {"openai-codex"}),
            "model": allow(model.get("default"), {"gpt-5.6-sol"}),
            "reasoning": allow(agent.get("reasoning_effort"), {"medium"}),
        },
        "fallback": {
            "enabled": fallback_enabled,
        },
        "host": _host_snapshot(),
        "watchdog": _watchdog_snapshot(),
        "healthbot": _healthbot_state(),
        "jobs": _jobs_summary(),
    }


def _fmt_bytes(value: float) -> str:
    value = float(value or 0)
    for suffix in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or suffix == "TiB":
            return f"{value:.1f} {suffix}"
        value /= 1024
    return "0 B"


def _fmt_number(value: float) -> str:
    value = float(value or 0)
    if abs(value) >= 1_000_000_000:
        return f"{value / 1_000_000_000:.1f}B"
    if abs(value) >= 1_000_000:
        return f"{value / 1_000_000:.1f}M"
    if abs(value) >= 1_000:
        return f"{value / 1_000:.1f}K"
    return str(int(value))


def handle_itstatus(raw_args: str):
    try:
        snapshot = _itstatus_snapshot()
    except Exception:  # noqa: BLE001 - command boundary must fail closed
        return "IT status is temporarily unavailable."
    gateway = snapshot["gateway"]
    model = snapshot["model"]
    fallback = snapshot["fallback"]
    host = snapshot["host"]
    watchdog = snapshot["watchdog"]
    jobs = snapshot["jobs"]
    watchdog_text = "healthy" if watchdog.get("ok") else f"degraded ({watchdog.get('issue_count', 0)} issues)"
    fallback_text = "unexpectedly enabled" if fallback.get("enabled") else "disabled"
    return "\n".join(
        [
            "*IT Support status*",
            "",
            f"`gateway` {gateway['state']} · {gateway['restarts']} restarts · {_fmt_bytes(gateway['memory_bytes'])}",
            f"`model` {model['provider']}/{model['model']} · reasoning {model['reasoning']}",
            f"`fallback` {fallback_text}",
            f"`host` disk {host['disk_pct']}% · memory {host['memory_pct']}%",
            f"`watchdog` {watchdog_text}",
            f"`healthbot` {snapshot['healthbot']}",
            f"`cron` {jobs['enabled']} enabled / {jobs['total']} total · {jobs['errors']} errors · {jobs['pending']} pending",
        ]
    )


def handle_jobs(raw_args: str):
    try:
        jobs = _jobs()
    except Exception:  # noqa: BLE001 - command boundary must fail closed
        return "Job status is temporarily unavailable."
    enabled = [job for job in jobs if job.get("enabled")]
    errors = [job for job in enabled if job.get("last_status") == "error"]
    pending = [job for job in enabled if job.get("last_status") is None]
    lines = ["*IT Support jobs*", "", f"{len(enabled)} enabled / {len(jobs)} total"]
    if errors:
        lines.append("")
        lines.append("*Errors*")
        known_errors = [SAFE_JOB_LABELS[job.get("id")] for job in errors if job.get("id") in SAFE_JOB_LABELS]
        lines.extend(f"• {label}: error" for label in known_errors[:8])
        unknown_errors = len(errors) - len(known_errors)
        if unknown_errors:
            noun = "error" if unknown_errors == 1 else "errors"
            lines.append(f"• {unknown_errors} unrecognized job {noun} (details withheld)")
    else:
        lines.extend(["", "✅ No enabled job errors."])
    if pending:
        lines.append("")
        lines.append("*Not run yet*")
        known_pending = [SAFE_JOB_LABELS[job.get("id")] for job in pending if job.get("id") in SAFE_JOB_LABELS]
        lines.extend(f"• {label}: not run yet" for label in known_pending[:8])
        unknown_pending = len(pending) - len(known_pending)
        if unknown_pending:
            lines.append(f"• {unknown_pending} unrecognized pending job(s) (details withheld)")
    return "\n".join(lines)


def _burn_reports() -> dict[int, dict] | None:
    result = _run([PYTHON_BIN, str(BURN_HELPER)], timeout=10)
    if result.returncode != 0:
        return None
    try:
        payload = json.loads(result.stdout)
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    reports = {}
    for days in (1, 7):
        report = payload.get(str(days))
        if (
            not isinstance(report, dict)
            or set(report) != BURN_METRICS
            or any(
                isinstance(value, bool) or not isinstance(value, int) or value < 0
                for value in report.values()
            )
        ):
            return None
        reports[days] = {key: report[key] for key in BURN_METRICS}
    return reports


def handle_burn(raw_args: str):
    reports = _burn_reports()
    if reports is None:
        return "Usage calculation is temporarily unavailable."
    day = reports[1]
    week = reports[7]

    def line(label: str, overview: dict) -> str:
        return (
            f"`{label}` {_fmt_number(overview.get('total_tokens', 0))} total · "
            f"{_fmt_number(overview.get('total_input_tokens', 0))} input · "
            f"{_fmt_number(overview.get('total_output_tokens', 0))} output · "
            f"{overview.get('total_sessions', 0)} sessions · {overview.get('total_messages', 0)} messages"
        )

    return "\n".join(
        [
            "*Token/context burn*",
            "",
            line("24h", day),
            line("7d", week),
            "",
            "_Total includes cache reads/writes; it is not the same as directly billed cost._",
        ]
    )


def _format_et(value: str | None) -> str:
    if not value:
        return "never"
    if not isinstance(value, str):
        return "unknown"
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.astimezone(ZoneInfo("America/New_York")).strftime("%Y-%m-%d %H:%M ET")
    except ValueError:
        return "unknown"


def _autonomy_snapshot() -> dict:
    mode = "unknown"
    mode_file = AUTONOMY_MEMORY / "checkpoints" / "autonomy_mode.md"
    try:
        for line in mode_file.read_text(encoding="utf-8").splitlines():
            if line.startswith("value:"):
                candidate = line.split(":", 1)[1].strip()
                mode = candidate if candidate in SAFE_AUTONOMY_MODES else "unknown/untrusted"
                break
    except OSError:
        pass

    heartbeat = next((job for job in _jobs() if job.get("id") == "990def203ebc"), {})
    watchdog = _watchdog_snapshot()
    try:
        records = sum(1 for path in AUTONOMY_MEMORY.rglob("*.md") if path.is_file())
    except OSError:
        records = 0
    board = _read_json(AUTONOMY_BOARD)
    active_lanes = ("scouting", "evaluating", "ready", "executing", "monitoring")
    active_cards = sum(len(value) for lane in active_lanes if isinstance((value := board.get(lane)), list))
    escalated = board.get("escalated")
    escalated_cards = len(escalated) if isinstance(escalated, list) else 0
    heartbeat_status = heartbeat.get("last_status")
    if heartbeat_status not in {"ok", "error", "running", "pending", "silent"}:
        heartbeat_status = "pending" if heartbeat_status is None else "unknown"
    return {
        "mode": mode,
        "heartbeat_status": heartbeat_status,
        "heartbeat_last_run": _format_et(heartbeat.get("last_run_at")),
        "watchdog_ok": watchdog.get("ok", False),
        "records": records,
        "active_cards": active_cards,
        "escalated_cards": escalated_cards,
    }


def handle_autonomy(raw_args: str):
    try:
        snapshot = _autonomy_snapshot()
    except Exception:  # noqa: BLE001 - command boundary must fail closed
        return "Autonomy status is temporarily unavailable."
    watchdog = "healthy" if snapshot["watchdog_ok"] else "degraded/unreadable"
    return "\n".join(
        [
            "*IT Support autonomy*",
            "",
            f"`mode` {snapshot['mode']}",
            f"`heartbeat` {snapshot['heartbeat_status']} · last {snapshot['heartbeat_last_run']}",
            f"`watchdog` {watchdog}",
            f"`memory` {snapshot['records']} records",
            f"`kanban` {snapshot['active_cards']} active · {snapshot['escalated_cards']} escalated",
        ]
    )


def register(ctx) -> None:
    ctx.register_command(
        "codexpool",
        handler=handle_codex,
        description="Show Codex OAuth pool usage (3 accounts, reset timers).",
    )
    ctx.register_command(
        "itstatus",
        handler=handle_itstatus,
        description="Show deterministic ITsupportBot and fleet health.",
    )
    ctx.register_command(
        "jobs",
        handler=handle_jobs,
        description="Show enabled IT support cron failures and pending jobs.",
    )
    ctx.register_command(
        "burn",
        handler=handle_burn,
        description="Show 24-hour and 7-day token/context usage.",
    )
    ctx.register_command(
        "autonomy",
        handler=handle_autonomy,
        description="Show IT support autonomy, watchdog, memory, and queue state.",
    )
