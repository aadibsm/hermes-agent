from __future__ import annotations

import importlib.util
from pathlib import Path

MODULE_PATH = Path(__file__).parents[1] / "scripts" / "autonomy_monitor.py"
spec = importlib.util.spec_from_file_location("autonomy_monitor", MODULE_PATH)
monitor = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(monitor)


class FakeResponse:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False


def test_gateway_signals_names_system_gateways_and_profile_processes(monkeypatch):
    def fake_sh(argv: list[str]) -> str:
        if argv[:2] == [monitor.SYSTEMCTL_BIN, "is-active"]:
            return "active"
        if argv[:2] == [monitor.PGREP_BIN, "-af"]:
            return (
                "100 python -m hermes_cli.main gateway run --replace\n"
                "101 python -m hermes_cli.main --profile aadibassistant gateway run\n"
                "102 python -m hermes_cli.main --profile deal-agent gateway run\n"
                "103 python -m hermes_cli.main --profile job-agent gateway run\n"
                "104 python -m hermes_cli.main --profile securityplus-coach gateway run\n"
                "105 python -m hermes_cli.main --profile stock-agent gateway run\n"
                "106 python -m hermes_cli.main gateway run"
            )
        raise AssertionError(f"unexpected command: {argv}")

    monkeypatch.setattr(monitor, "sh", fake_sh)

    assert monitor.gateway_signals() == [
        "gateways.up=aadibassistant,deal-agent,default,itsupportbot,job-agent,securityplus-coach,stock-agent"
    ]


def test_gateway_signals_omits_inactive_system_gateway(monkeypatch):
    def fake_sh(argv: list[str]) -> str:
        if argv[:2] == [monitor.SYSTEMCTL_BIN, "is-active"]:
            return "inactive" if argv[-1] == "hermes-gateway-itsupportbot.service" else "active"
        if argv[:2] == [monitor.PGREP_BIN, "-af"]:
            return "200 python -m hermes_cli.main --profile deal-agent gateway run"
        raise AssertionError(f"unexpected command: {argv}")

    monkeypatch.setattr(monitor, "sh", fake_sh)

    assert monitor.gateway_signals() == ["gateways.up=deal-agent,default"]


def test_watchdog_signals_are_stable_health_state(monkeypatch):
    monkeypatch.setattr(monitor, "read_json_if_accessible", lambda path: {"issues": [], "actions": []})
    assert monitor.watchdog_signals() == ["watchdog.all_ok"]

    monkeypatch.setattr(
        monitor,
        "read_json_if_accessible",
        lambda path: {"issues": ["changing detail 123 seconds ago"], "actions": []},
    )
    assert monitor.watchdog_signals() == ["watchdog.degraded=true"]


def test_watchdog_signals_report_unreadable_state(monkeypatch):
    monkeypatch.setattr(monitor, "read_json_if_accessible", lambda path: None)
    assert monitor.watchdog_signals() == ["watchdog.state_unreadable"]


def test_read_json_rejects_non_mapping_payload(tmp_path):
    payload = tmp_path / "payload.json"
    payload.write_text('["PRIVATE_SENTINEL"]')
    assert monitor.read_json_if_accessible(payload) is None


def test_codex_account_allowlist_matches_rotation_pool():
    assert monitor.CODEX_ACCOUNTS == ("tabiaadib", "smaadibusa", "aadibsmusa1")


def test_codex_signals_ignore_unrecognized_account_labels(monkeypatch):
    monkeypatch.setattr(
        monitor,
        "read_json_if_accessible",
        lambda path: {
            "all_touched": False,
            "active": "retired-account",
            "accounts": {
                "retired-account": {"touched": False, "http": 200, "used_percent": 10},
                "PRIVATE_ACCOUNT_SENTINEL": {"touched": False, "http": "PRIVATE_HTTP", "used_percent": 99},
            },
        },
    )
    output = "\n".join(monitor.codex_signals())
    assert "PRIVATE_ACCOUNT_SENTINEL" not in output
    assert "PRIVATE_HTTP" not in output


def test_codex_signals_distinguish_ambiguous_touch_from_pending(monkeypatch):
    monkeypatch.setattr(
        monitor,
        "read_json_if_accessible",
        lambda path: {
            "all_touched": False,
            "active": "tabiaadib",
            "accounts": {
                "tabiaadib": {"touched": False, "touch_status": "ambiguous", "http": 200},
                "smaadibusa": {"touched": False, "touch_status": "untouched", "http": 200},
                "aadibsmusa1": {"touched": True, "touch_status": "confirmed", "http": 200},
            },
        },
    )

    output = monitor.codex_signals()

    assert "codex.touch_ambiguous=tabiaadib" in output
    assert "codex.pending_windows=smaadibusa" in output
    assert "codex.pending_windows=tabiaadib,smaadibusa" not in output


def test_codex_signals_ignore_nonfinite_and_oversized_usage(monkeypatch):
    monkeypatch.setattr(
        monitor,
        "read_json_if_accessible",
        lambda path: {
            "all_touched": False,
            "active": "tabiaadib",
            "accounts": {
                "tabiaadib": {"touched": True, "touch_status": "confirmed", "http": 200, "used_percent": float("inf")},
                "smaadibusa": {"touched": True, "touch_status": "confirmed", "http": 200, "used_percent": 10**10000},
                "aadibsmusa1": {"touched": True, "touch_status": "confirmed", "http": 200, "used_percent": 20},
            },
        },
    )

    output = monitor.codex_signals()

    assert "codex.usage_band" not in "\n".join(output)


def test_gateway_signals_aggregate_unrecognized_profiles(monkeypatch):
    def fake_sh(argv: list[str]) -> str:
        if argv[:2] == [monitor.SYSTEMCTL_BIN, "is-active"]:
            return "active"
        if argv[:2] == [monitor.PGREP_BIN, "-af"]:
            return (
                "1 python -m hermes_cli.main --profile deal-agent gateway run\n"
                "2 python -m hermes_cli.main --profile PRIVATE_PROFILE_SENTINEL gateway run"
            )
        return ""

    monkeypatch.setattr(monitor, "sh", fake_sh)
    output = monitor.gateway_signals()
    assert "PRIVATE_PROFILE_SENTINEL" not in "\n".join(output)
    assert "gateways.unrecognized_count=1" in output


def test_gateway_signals_ignore_malformed_profile_switch(monkeypatch):
    def fake_sh(argv: list[str]) -> str:
        if argv[:2] == [monitor.SYSTEMCTL_BIN, "is-active"]:
            return "inactive"
        if argv[:2] == [monitor.PGREP_BIN, "-af"]:
            return "1 python -m hermes_cli.main --profile\n"
        return ""

    monkeypatch.setattr(monitor, "sh", fake_sh)
    output = monitor.gateway_signals()
    assert output == [
        "gateways.up=",
        "gateways.malformed_process_count=1",
    ]


def test_systemd_signals_report_count_not_raw_unit_names(monkeypatch):
    monkeypatch.setattr(
        monitor,
        "sh",
        lambda argv: "PRIVATE_UNIT_SENTINEL.service loaded failed failed private",
    )
    output = monitor.systemd_signals()
    assert output == ["systemd.failed_count=1"]
    assert "PRIVATE_UNIT_SENTINEL" not in "\n".join(output)


def test_systemd_signals_fail_closed_when_probe_is_unavailable(monkeypatch):
    monkeypatch.setattr(monitor, "sh", lambda argv: None)

    assert monitor.systemd_signals() == ["systemd.failed_units=unknown"]


def test_health_signals_reject_list_json_without_crashing(monkeypatch):
    monkeypatch.setattr(monitor.urllib.request, "urlopen", lambda *args, **kwargs: FakeResponse())
    monkeypatch.setattr(monitor.json, "load", lambda response: ["PRIVATE_SENTINEL"])

    assert monitor.health_signals() == ["healthbot.unreachable=true"]


def test_monitor_uses_absolute_system_probe_binaries(monkeypatch):
    calls = []

    def fake_sh(argv: list[str]) -> str:
        calls.append(argv)
        if argv[0] == "/usr/bin/df":
            return "Use%\n64%"
        return ""

    monkeypatch.setattr(monitor, "sh", fake_sh)
    monitor.gateway_signals()
    monitor.systemd_signals()
    monitor.disk_signals()

    assert calls
    assert all(call[0] in {"/usr/bin/systemctl", "/usr/bin/pgrep", "/usr/bin/df"} for call in calls)
