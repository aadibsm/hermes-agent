from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).parents[1] / "scripts" / "autonomy.py"
spec = importlib.util.spec_from_file_location("autonomy", MODULE_PATH)
autonomy = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(autonomy)


def test_safe_component_rejects_traversal_and_control_values():
    for value in ("../escape", "/absolute", "..", "bad/name", "bad\nname", "", "x" * 65):
        try:
            autonomy._safe_component(value, "id")
        except ValueError:
            pass
        else:
            raise AssertionError(f"accepted unsafe component: {value!r}")

    assert autonomy._safe_component("20260831-codex", "id") == "20260831-codex"


def test_atomic_write_flushes_file_and_directory(tmp_path, monkeypatch):
    fsync_calls = []
    monkeypatch.setattr(autonomy.os, "fsync", lambda fd: fsync_calls.append(fd))
    target = tmp_path / "decisions" / "safe.md"

    autonomy._atomic_write(target, "safe body\n")

    assert target.read_text() == "safe body\n"
    assert len(fsync_calls) >= 2


def test_atomic_write_rejects_symlinked_parent_directory(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    profile = tmp_path / "profile"
    profile.mkdir()
    (profile / "decisions").symlink_to(outside, target_is_directory=True)

    with pytest.raises(OSError):
        autonomy._atomic_write(profile / "decisions" / "escape.md", "must not escape\n")

    assert not (outside / "escape.md").exists()


def test_mempalace_helper_uses_fixed_environment(monkeypatch):
    captured = {}

    class FakeProcess:
        def __init__(self):
            self.stdout = self._pipe(b"ok")
            self.stderr = self._pipe(b"")
            self.returncode = 0

        @staticmethod
        def _pipe(data):
            read_fd, write_fd = os.pipe()
            os.write(write_fd, data)
            os.close(write_fd)
            return os.fdopen(read_fd, "rb")

        def wait(self, timeout=None):
            return self.returncode

        def kill(self):
            self.returncode = -9

    def fake_popen(argv, **kwargs):
        captured.update(kwargs)
        captured["argv"] = argv
        return FakeProcess()

    monkeypatch.setattr(autonomy.subprocess, "Popen", fake_popen)
    result = autonomy.mp("status")

    assert result.returncode == 0
    assert captured["env"] == autonomy.SAFE_ENV
    assert "OPENAI_API_KEY" not in captured["env"]
    assert captured["shell"] is False


def test_mempalace_helper_rejects_oversized_output(monkeypatch):
    monkeypatch.setattr(autonomy, "MAX_HELPER_OUTPUT", 8)

    class FakeProcess:
        def __init__(self):
            self.stdout = self._pipe(b"x" * 9)
            self.stderr = self._pipe(b"")
            self.returncode = 0

        @staticmethod
        def _pipe(data):
            read_fd, write_fd = os.pipe()
            os.write(write_fd, data)
            os.close(write_fd)
            return os.fdopen(read_fd, "rb")

        def wait(self, timeout=None):
            return self.returncode

        def kill(self):
            self.returncode = -9

    monkeypatch.setattr(autonomy.subprocess, "Popen", lambda argv, **kwargs: FakeProcess())

    result = autonomy.mp("status")

    assert result.stdout == ""
    assert result.stderr == "output_limit"
