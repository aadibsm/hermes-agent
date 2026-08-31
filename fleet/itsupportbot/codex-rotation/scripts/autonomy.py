#!/usr/bin/env python3
"""Autonomy wrapper for itsupportbot (hermes-autonomy skill).

Domain: Codex credential pool + fleet operational decisions.
All memory lives under this profile's state/ tree; never shared.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import selectors
import stat
import subprocess  # nosec B404 - fixed profile-local helper only
import sys
import time
from pathlib import Path

PROFILE_HOME = Path("/home/hermes/.hermes/profiles/itsupportbot")
MP_BIN = PROFILE_HOME / "bin" / "mempalace"
PALACE = PROFILE_HOME / "state" / "autonomy-palace"
CORPUS = PROFILE_HOME / "state" / "autonomy-memory"
KANBAN_FILE = PROFILE_HOME / "state" / "autonomy-kanban" / "board.json"
DECISIONS_DIR = CORPUS / "decisions"
DOMAIN_SOURCE = PROFILE_HOME / "state" / "codex-usage.json"
SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
SAFE_ENV = {
    "HOME": "/home/hermes",
    "PATH": SAFE_PATH,
    "LANG": "C",
    "LC_ALL": "C",
    "PYTHONNOUSERSITE": "1",
}
MAX_HELPER_OUTPUT = 64 * 1024
_SAFE_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")


def _run_bounded(argv: list[str], timeout: float = 30) -> subprocess.CompletedProcess[str]:
    """Run the fixed mempalace helper with bounded output and clean env."""
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
    returncode = process.returncode if process.returncode is not None else 124
    stdout = bytes(buffers["stdout"]).decode("utf-8", "replace")
    stderr = bytes(buffers["stderr"]).decode("utf-8", "replace")
    if reason:
        stdout = ""
        stderr = reason
    return subprocess.CompletedProcess(argv, returncode, stdout, stderr)


def mp(*args: str) -> subprocess.CompletedProcess:
    argv = [str(MP_BIN), "--palace", str(PALACE), *args]
    try:
        return _run_bounded(argv)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return subprocess.CompletedProcess(argv, 124, "", type(exc).__name__)


def _mine_file(path: Path) -> None:
    # mempalace mines directories, not individual files; the corpus is small
    # so a full-dir mine is cheap and idempotent.
    result = mp("mine", str(CORPUS))
    if result.returncode != 0:
        print(f"mine_failed: {result.stderr.strip()[:200]}", file=sys.stderr)


_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | _NOFOLLOW


def _open_secure_dir(path: Path, *, create: bool) -> int:
    """Open every directory component without following a symlink."""
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


def _read_text(path: Path) -> str:
    file_fd = _open_regular(path, os.O_RDONLY)
    try:
        with os.fdopen(file_fd, encoding="utf-8") as handle:
            file_fd = -1
            return handle.read()
    finally:
        if file_fd >= 0:
            os.close(file_fd)


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


def _atomic_write(path: Path, data: str) -> None:
    """Atomically write a profile-local record through a secure directory fd."""
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
        target_mode = stat.S_IMODE(existing_stat.st_mode) if existing_stat is not None else 0o600
        tmp_fd, tmp_name = _create_temp(parent_fd, path.name)
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as handle:
            tmp_fd = -1
            handle.write(data)
            handle.flush()
            os.fchmod(handle.fileno(), target_mode)
            if existing_stat is not None and (
                existing_stat.st_uid != os.geteuid() or existing_stat.st_gid != os.getegid()
            ):
                try:
                    os.fchown(handle.fileno(), existing_stat.st_uid, existing_stat.st_gid)
                except OSError as exc:
                    raise OSError("cannot preserve destination ownership") from exc
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


def _safe_component(value: str, kind: str) -> str:
    """Accept only a bounded filename component; reject traversal/control data."""
    if not isinstance(value, str) or not _SAFE_COMPONENT.fullmatch(value):
        raise ValueError(f"invalid {kind}")
    return value


def cmd_bootstrap(args: argparse.Namespace) -> None:
    """Seed the palace with current Codex pool state."""
    try:
        payload = json.loads(_read_text(DOMAIN_SOURCE))
    except FileNotFoundError:
        print("domain source missing")
        return
    except (OSError, UnicodeError, ValueError):
        print("domain source unavailable")
        return
    records = []
    for label, info in sorted((payload.get("accounts") or {}).items()):
        records.append(
            f"# codex:{label}\n"
            f"used_percent: {info.get('used_percent')}\n"
            f"active: {payload.get('active') == label}\n"
            f"checked_at: {info.get('checked_at')}\n"
            f"type: codex_usage_snapshot\n"
        )
    target = CORPUS / "snapshots" / "codex-pool-current.md"
    _atomic_write(target, "\n".join(records))
    _mine_file(target)
    print(f"bootstrap_ok: {len(records)} credential records mined")


def cmd_search(args: argparse.Namespace) -> None:
    query = " ".join(args.query)
    result = mp("search", query, "--results", str(args.results))
    print(result.stdout or result.stderr)


def cmd_store(args: argparse.Namespace) -> None:
    """Record a decision with rationale; mined into the palace immediately."""
    try:
        decision_id = _safe_component(args.id, "decision id")
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return
    body = (
        f"# decision:{decision_id}\n"
        f"status: {args.status or 'committed'}\n"
        f"date: {args.date}\n\n{args.note}\n"
    )
    target = DECISIONS_DIR / f"{decision_id}.md"
    _atomic_write(target, body)
    _mine_file(target)
    print(f"stored: {decision_id}")


def cmd_checkpoint(args: argparse.Namespace) -> None:
    try:
        checkpoint_key = _safe_component(args.key, "checkpoint key")
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return
    body = f"# checkpoint:{checkpoint_key}\nvalue: {args.value}\ntype: checkpoint\n"
    target = CORPUS / "checkpoints" / f"{checkpoint_key}.md"
    _atomic_write(target, body)
    _mine_file(target)
    print(f"checkpoint: {checkpoint_key}={args.value}")


def _load_board() -> dict:
    empty = {
        "backlog": [], "scouting": [], "evaluating": [],
        "ready": [], "executing": [], "monitoring": [],
        "done": [], "blocked": [], "escalated": [],
    }
    try:
        value = json.loads(_read_text(KANBAN_FILE))
    except (FileNotFoundError, OSError, UnicodeError, ValueError):
        return empty
    return value if isinstance(value, dict) else empty


def cmd_kanban_list(args: argparse.Namespace) -> None:
    print(json.dumps(_load_board(), indent=2))


def cmd_kanban_move(args: argparse.Namespace) -> None:
    board = _load_board()
    card = None
    for lane, cards in board.items():
        match = [c for c in cards if isinstance(c, dict) and c.get("id") == args.id]
        if not match and isinstance(cards, list):
            match = [c for c in cards if isinstance(c, str) and c == args.id]
            match = [{"id": args.id}] if match else []
        for item in match:
            card = item
            board[lane] = [c for c in cards if c is not item]
            break
        if card:
            break
    if card is None:
        card = {"id": args.id}
    card.setdefault("history", []).append(args.lane)
    board.setdefault(args.lane, []).append(card)
    _atomic_write(KANBAN_FILE, json.dumps(board, indent=2, sort_keys=True))
    print(f"moved {args.id} -> {args.lane}")


def cmd_status(args: argparse.Namespace) -> None:
    print("=== Palace ===")
    result = mp("status")
    print(result.stdout or result.stderr)
    print("\n=== Latest checkpoints ===")
    result = mp("search", "checkpoint:", "--results", "5")
    print(result.stdout or "(none)")
    board = _load_board()
    counts = {k: len(v) for k, v in board.items() if v}
    print("\n=== Kanban ===")
    print(json.dumps(counts or {}, indent=2))


def cmd_evolve(args: argparse.Namespace) -> None:
    print("evolve: disabled by cost policy (enable explicitly to run DSPy MIPRO)")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("bootstrap")
    p = sub.add_parser("search"); p.add_argument("query", nargs="+")
    p.add_argument("--results", type=int, default=5)
    p = sub.add_parser("store"); p.add_argument("--id", required=True)
    p.add_argument("--note", required=True); p.add_argument("--status")
    p.add_argument("--date", default=__import__("datetime").date.today().isoformat())
    p = sub.add_parser("checkpoint"); p.add_argument("--key", required=True)
    p.add_argument("--value", required=True)
    sub.add_parser("kanban-list")
    p = sub.add_parser("kanban-move"); p.add_argument("--id", required=True)
    p.add_argument("--lane", required=True)
    sub.add_parser("status")
    sub.add_parser("evolve")
    args = parser.parse_args()
    {"bootstrap": cmd_bootstrap, "search": cmd_search, "store": cmd_store,
     "checkpoint": cmd_checkpoint, "kanban-list": cmd_kanban_list,
     "kanban-move": cmd_kanban_move, "status": cmd_status,
     "evolve": cmd_evolve}[args.cmd](args)
