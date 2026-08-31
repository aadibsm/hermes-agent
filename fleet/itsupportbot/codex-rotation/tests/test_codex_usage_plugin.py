from __future__ import annotations

import importlib.util
import json
import math
from pathlib import Path

PLUGIN_PATH = Path(__file__).parents[1] / "plugins" / "codex-usage" / "__init__.py"
spec = importlib.util.spec_from_file_location("codex_usage_plugin", PLUGIN_PATH)
plugin = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(plugin)


class FakeHealthResponse:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False


def test_profile_and_burn_helper_paths_ignore_untrusted_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "UNTRUSTED_PROFILE_HOME"))
    isolated_spec = importlib.util.spec_from_file_location("codex_usage_isolated", PLUGIN_PATH)
    isolated = importlib.util.module_from_spec(isolated_spec)
    assert isolated_spec.loader is not None
    isolated_spec.loader.exec_module(isolated)

    assert isolated.PROFILE_HOME == Path("/home/hermes/.hermes/profiles/itsupportbot")
    assert isolated.BURN_HELPER == Path(
        "/home/hermes/.hermes/profiles/itsupportbot/scripts/itstatus_burn.py"
    )


def test_itstatus_reports_core_health_without_secrets(monkeypatch):
    monkeypatch.setattr(
        plugin,
        "_itstatus_snapshot",
        lambda: {
            "gateway": {"state": "active", "restarts": 0, "memory_bytes": 1024**3},
            "model": {"provider": "openai-codex", "model": "gpt-5.6-sol", "reasoning": "medium"},
            "fallback": {"enabled": False},
            "host": {"disk_pct": 64, "memory_pct": 38},
            "watchdog": {"ok": True, "issue_count": 0},
            "healthbot": "healthy",
            "jobs": {"total": 6, "enabled": 6, "errors": 0, "pending": 1},
        },
    )

    output = plugin.handle_itstatus("")

    assert "openai-codex/gpt-5.6-sol" in output
    assert "`fallback` disabled" in output
    assert "deepseek" not in output.lower()
    assert "gateway" in output and "active" in output
    assert "disk 64%" in output and "memory 38%" in output
    assert "6 enabled" in output and "0 errors" in output
    assert "token" not in output.lower()
    assert "api_key" not in output.lower()


def test_itstatus_health_probe_rejects_list_json_without_crashing(monkeypatch):
    monkeypatch.setattr(plugin.urllib.request, "urlopen", lambda *args, **kwargs: FakeHealthResponse())
    monkeypatch.setattr(plugin.json, "load", lambda response: ["PRIVATE_SENTINEL"])

    output = plugin._healthbot_state()

    assert output == "unreachable from Hermes"
    assert "PRIVATE_SENTINEL" not in output


def test_jobs_reports_errors_and_pending_jobs(tmp_path, monkeypatch):
    jobs_file = tmp_path / "jobs.json"
    jobs_file.write_text(
        json.dumps(
            {
                "jobs": [
                    {"id": "ok", "name": "Healthy", "enabled": True, "last_status": "ok"},
                    {"id": "d3d1e28e642e", "name": "untrusted name", "enabled": True, "last_status": "error"},
                    {"id": "e7b1f895686e", "name": "untrusted pending", "enabled": True, "last_status": None},
                    {"id": "unknown", "name": "SECRET_TOKEN_DO_NOT_RENDER", "enabled": True, "last_status": "error"},
                    {"id": "off", "name": "Disabled", "enabled": False, "last_status": "error"},
                ]
            }
        )
    )
    monkeypatch.setattr(plugin, "JOBS_FILE", jobs_file)

    output = plugin.handle_jobs("")

    assert "4 enabled / 5 total" in output
    assert "Codex quota watchdog" in output and "error" in output
    assert "Weekly fleet-wide Hermes update" in output and "not run yet" in output
    assert "1 unrecognized job error" in output
    assert "SECRET_TOKEN_DO_NOT_RENDER" not in output
    assert "untrusted name" not in output
    assert "Disabled" not in output


def test_burn_reports_24h_and_7d_cache_aware_totals(monkeypatch):
    reports = {
        1: {
            "total_sessions": 7,
            "total_messages": 857,
            "total_input_tokens": 1_526_804,
            "total_output_tokens": 255_351,
            "total_cache_read_tokens": 41_000_000,
            "total_cache_write_tokens": 28_352,
            "total_tokens": 42_810_507,
        },
        7: {
            "total_sessions": 25,
            "total_messages": 2251,
            "total_input_tokens": 5_081_989,
            "total_output_tokens": 670_885,
            "total_cache_read_tokens": 116_000_000,
            "total_cache_write_tokens": 158_656,
            "total_tokens": 121_911_530,
        },
    }
    monkeypatch.setattr(plugin, "_burn_reports", lambda: reports)

    output = plugin.handle_burn("")

    assert "24h" in output and "42.8M total" in output
    assert "7d" in output and "121.9M total" in output
    assert "1.5M input" in output and "255.4K output" in output
    assert "includes cache" in output.lower()


def test_burn_fails_safely_when_helper_times_out(monkeypatch):
    monkeypatch.setattr(plugin, "_burn_reports", lambda: None)
    assert plugin.handle_burn("") == "Usage calculation is temporarily unavailable."


def test_burn_rejects_malformed_helper_metrics(monkeypatch):
    class Result:
        returncode = 0
        stdout = '{"1":{"total_tokens":"SECRET"},"7":{"total_tokens":1}}'

    monkeypatch.setattr(plugin, "_run", lambda argv, timeout=10: Result())
    assert plugin._burn_reports() is None


def test_burn_uses_fixed_profile_interpreter(monkeypatch):
    captured = {}

    class Result:
        returncode = 1
        stdout = ""

    def fake_run(argv, timeout=10):
        captured["argv"] = argv
        return Result()

    monkeypatch.setattr(plugin, "_run", fake_run)
    assert plugin._burn_reports() is None
    assert captured["argv"][0] == plugin.PYTHON_BIN
    assert captured["argv"][1] == str(plugin.BURN_HELPER)


def test_codexpool_handles_nonfinite_numbers_without_crashing(tmp_path, monkeypatch):
    cache = tmp_path / "usage.json"
    cache.write_text(
        json.dumps(
            {
                "active": "tabiaadib",
                "accounts": {
                    "tabiaadib": {"used_percent": math.nan, "reset_epoch": math.inf, "ok": True},
                },
            }
        )
    )
    monkeypatch.setattr(plugin, "USAGE_CACHE", cache)

    output = plugin.handle_codex("")

    assert "nan" not in output.lower()
    assert "inf" not in output.lower()
    assert "?" in output


def test_autonomy_reports_mode_heartbeat_watchdog_and_queue(monkeypatch):
    monkeypatch.setattr(
        plugin,
        "_autonomy_snapshot",
        lambda: {
            "mode": "monitor-only-v1",
            "heartbeat_status": "ok",
            "heartbeat_last_run": "2026-08-23 10:44 ET",
            "watchdog_ok": True,
            "records": 5,
            "active_cards": 2,
            "escalated_cards": 1,
        },
    )

    output = plugin.handle_autonomy("")

    assert "monitor-only-v1" in output
    assert "heartbeat" in output and "ok" in output
    assert "5 records" in output
    assert "2 active" in output and "1 escalated" in output


def test_codexpool_renders_current_account_labels(tmp_path, monkeypatch):
    cache = tmp_path / "usage.json"
    cache.write_text(
        json.dumps(
            {
                "active": "aadibsmusa1",
                "accounts": {
                    "tabiaadib": {"used_percent": 1, "ok": True},
                    "smaadibusa": {"used_percent": 2, "ok": True},
                    "aadibsmusa1": {"used_percent": 3, "ok": True},
                },
            }
        )
    )
    monkeypatch.setattr(plugin, "USAGE_CACHE", cache)
    output = plugin.handle_codex("")
    assert all(label in output for label in ("tabiaadib", "smaadibusa", "aadibsmusa1"))
    assert "retired-account" not in output


def test_codexpool_disables_raw_json_and_hides_read_errors(tmp_path, monkeypatch):
    cache = tmp_path / "usage.json"
    cache.write_text('{"secret":"do-not-render"}')
    monkeypatch.setattr(plugin, "USAGE_CACHE", cache)
    assert plugin.handle_codex("json") == "Raw JSON output is disabled for privacy."
    assert "do-not-render" not in plugin.handle_codex("json")

    monkeypatch.setattr(plugin, "USAGE_CACHE", tmp_path)
    output = plugin.handle_codex("")
    assert output == "Could not read usage cache safely."
    assert str(tmp_path) not in output


def test_codexpool_rejects_malformed_cache_shapes(tmp_path, monkeypatch):
    cache = tmp_path / "usage.json"
    monkeypatch.setattr(plugin, "USAGE_CACHE", cache)
    for content in ("[]", '{"accounts":"SECRET_VALUE"}'):
        cache.write_text(content)
        output = plugin.handle_codex("")
        assert output == "Usage cache is unavailable."
        assert "SECRET_VALUE" not in output


def test_autonomy_rejects_untrusted_mode_and_malformed_board(tmp_path, monkeypatch):
    memory = tmp_path / "memory"
    checkpoint = memory / "checkpoints"
    checkpoint.mkdir(parents=True)
    (checkpoint / "autonomy_mode.md").write_text("value: SECRET_MODE_DO_NOT_RENDER\n")
    board = tmp_path / "board.json"
    board.write_text('{"scouting":"not-a-list","escalated":{"bad":true}}')
    monkeypatch.setattr(plugin, "AUTONOMY_MEMORY", memory)
    monkeypatch.setattr(plugin, "AUTONOMY_BOARD", board)
    monkeypatch.setattr(plugin, "_jobs", list)
    monkeypatch.setattr(plugin, "_watchdog_snapshot", lambda: {"ok": True})

    snapshot = plugin._autonomy_snapshot()
    output = plugin.handle_autonomy("")

    assert snapshot["mode"] == "unknown/untrusted"
    assert snapshot["active_cards"] == 0
    assert snapshot["escalated_cards"] == 0
    assert "SECRET_MODE_DO_NOT_RENDER" not in output


def test_malformed_time_and_disk_state_fail_safely(monkeypatch):
    assert plugin._format_et({"not": "a string"}) == "unknown"
    monkeypatch.setattr(plugin.shutil, "disk_usage", lambda path: (_ for _ in ()).throw(OSError("no disk")))
    host = plugin._host_snapshot()
    assert host["disk_pct"] == 0


def test_register_exposes_all_zero_token_commands():
    class FakeContext:
        def __init__(self):
            self.commands = {}

        def register_command(self, name, handler, description="", args_hint=""):
            self.commands[name] = handler

    ctx = FakeContext()
    plugin.register(ctx)

    assert set(ctx.commands) == {"codexpool", "itstatus", "jobs", "burn", "autonomy"}


def test_watchdog_snapshot_never_uses_sudo_fallback(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(plugin, "WATCHDOG_STATE", tmp_path / "unreadable.json")
    monkeypatch.setattr(
        plugin,
        "_run",
        lambda argv, timeout=10: calls.append(argv),
    )

    snapshot = plugin._watchdog_snapshot()

    assert snapshot["readable"] is False
    assert calls == []


def test_service_snapshot_uses_absolute_systemctl(monkeypatch):
    calls = []

    def fake_run(argv, timeout=10):
        calls.append(argv)
        return plugin.subprocess.CompletedProcess(argv, 0, "inactive\n", "")

    monkeypatch.setattr(plugin, "_run", fake_run)
    plugin._service_snapshot()

    assert calls
    assert all(call[0] == "/usr/bin/systemctl" for call in calls)
