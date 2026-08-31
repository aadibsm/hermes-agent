from __future__ import annotations

import importlib.util
import json
import math
import os
from copy import deepcopy
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).parents[1] / "scripts" / "codex-account-rotation.py"
spec = importlib.util.spec_from_file_location("codex_account_rotation", MODULE_PATH)
rotation = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(rotation)


class FakeResponse:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def read(self) -> bytes:
        return json.dumps(
            {
                "plan_type": "test",
                "rate_limit": {
                    "primary_window": {
                        "used_percent": 1,
                        "reset_at": 2_000_000_000,
                        "limit_window_seconds": 18_000,
                    }
                },
            }
        ).encode()


def test_usage_probe_ignores_credential_supplied_base_url(monkeypatch):
    captured = {}

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        return FakeResponse()

    monkeypatch.setattr(rotation.urllib.request, "urlopen", fake_urlopen)

    result = rotation.usage_probe(
        {
            "access_token": "synthetic-test-token",
            "base_url": "https://attacker.invalid/codex",
        }
    )

    assert result["ok"] is True
    assert captured["url"] == "https://chatgpt.com/backend-api/wham/usage"


def test_usage_probe_rejects_nonfinite_or_out_of_range_percent(monkeypatch):
    class PayloadResponse(FakeResponse):
        def __init__(self, payload):
            self.payload = payload

        def read(self):
            return json.dumps(self.payload).encode()

    for used_percent in (math.nan, math.inf, -1, 101):
        monkeypatch.setattr(
            rotation.urllib.request,
            "urlopen",
            lambda request, timeout, used_percent=used_percent: PayloadResponse(
                {
                    "rate_limit": {
                        "primary_window": {
                            "used_percent": used_percent,
                            "reset_at": 2_000_000_000,
                        }
                    }
                }
            ),
        )
        result = rotation.usage_probe({"access_token": "synthetic-test-token"})
        assert result["ok"] is False
        assert result["used_percent"] is None


def test_auth_roots_rejects_symlinked_auth_store(tmp_path, monkeypatch):
    profile_root = tmp_path / "profile"
    profile_root.mkdir()
    outside = tmp_path / "other-profile-auth.json"
    outside.write_text("{}")
    (profile_root / "auth.json").symlink_to(outside)
    monkeypatch.setattr(rotation, "LOCAL_ROOT", profile_root)

    assert rotation.auth_roots() == []


def test_atomic_json_rejects_symlinked_parent_directory(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    profile = tmp_path / "profile"
    profile.mkdir()
    (profile / "state").symlink_to(outside, target_is_directory=True)

    with pytest.raises(OSError):
        rotation.atomic_json(profile / "state" / "state.json", {"changed": True})

    assert not (outside / "state.json").exists()


def test_atomic_json_fails_closed_when_existing_owner_cannot_be_restored(tmp_path, monkeypatch):
    destination = tmp_path / "state.json"
    destination.write_text('{"before": true}')
    existing = os.stat(destination)
    monkeypatch.setattr(rotation.os, "geteuid", lambda: existing.st_uid + 1)
    monkeypatch.setattr(
        rotation.os,
        "fchown",
        lambda *args: (_ for _ in ()).throw(PermissionError("synthetic chown failure")),
    )

    with pytest.raises(OSError):
        rotation.atomic_json(destination, {"changed": True})

    assert destination.read_text() == '{"before": true}'


def test_atomic_json_rejects_symlink_destination(tmp_path):
    outside = tmp_path / "outside.json"
    outside.write_text("keep")
    destination = tmp_path / "destination.json"
    destination.symlink_to(outside)

    with pytest.raises(OSError):
        rotation.atomic_json(destination, {"changed": True})

    assert outside.read_text() == "keep"


def test_append_log_rejects_symlink_destination(tmp_path, monkeypatch):
    outside = tmp_path / "outside.log"
    outside.write_text("keep\n")
    log_path = tmp_path / "rotation.log"
    log_path.symlink_to(outside)
    monkeypatch.setattr(rotation, "LOG_PATH", log_path)

    with pytest.raises(OSError):
        rotation.append_log("do not write")

    assert outside.read_text() == "keep\n"


def test_lock_rejects_symlink_destination(tmp_path, monkeypatch):
    outside = tmp_path / "outside.lock"
    outside.write_text("keep")
    lock_path = tmp_path / "rotation.lock"
    lock_path.symlink_to(outside)
    monkeypatch.setattr(rotation, "LOCK_PATH", lock_path)

    with pytest.raises(OSError):
        rotation.open_lock_handle()

    assert outside.read_text() == "keep"


def test_agents_annotation_does_not_follow_symlink(tmp_path, monkeypatch):
    profile_root = tmp_path / "profile"
    profile_root.mkdir()
    outside = tmp_path / "outside.md"
    outside.write_text("keep")
    (profile_root / "AGENTS.md").symlink_to(outside)
    monkeypatch.setattr(rotation, "LOCAL_ROOT", profile_root)
    monkeypatch.setattr(rotation, "append_log", lambda message: None)

    rotation.refresh_agents_blocks(
        {
            "accounts": {
                label: {"used_percent": 1, "ok": True, "reset_epoch": 2_000_000_000}
                for label in rotation.ORDER
            },
            "active": rotation.PREFERRED,
        }
    )

    assert outside.read_text() == "keep"
    assert (profile_root / "AGENTS.md").is_symlink()


def test_agents_annotation_is_atomic_and_preserves_restrictive_mode(tmp_path, monkeypatch):
    profile_root = tmp_path / "profile"
    profile_root.mkdir()
    agents = profile_root / "AGENTS.md"
    agents.write_text("# profile context\n")
    agents.chmod(0o600)
    monkeypatch.setattr(rotation, "LOCAL_ROOT", profile_root)
    monkeypatch.setattr(rotation, "append_log", lambda message: None)
    replacements = []
    real_replace = rotation.os.replace

    def record_replace(*args, **kwargs):
        replacements.append((args, kwargs))
        return real_replace(*args, **kwargs)

    monkeypatch.setattr(rotation.os, "replace", record_replace)
    payload = {
        "accounts": {
            label: {"used_percent": 1, "ok": True, "reset_epoch": 2_000_000_000}
            for label in rotation.ORDER
        },
        "active": rotation.PREFERRED,
    }

    rotation.refresh_agents_blocks(payload)

    assert replacements
    assert os.stat(agents).st_mode & 0o777 == 0o600
    assert rotation.BEGIN_MARK in agents.read_text()


def _main_fixture(monkeypatch, tmp_path, probes, initial_state=None):
    credentials = {label: {"label": label, "access_token": "synthetic"} for label in rotation.ORDER}
    stored = {"value": deepcopy(initial_state or {"version": 1, "accounts": {}, "active": None})}
    saves = []

    monkeypatch.setattr(rotation, "LOCK_PATH", tmp_path / "rotation.lock")
    monkeypatch.setattr(rotation, "STATE_PATH", tmp_path / "rotation-state.json")
    monkeypatch.setattr(rotation, "LOG_PATH", tmp_path / "rotation.log")
    monkeypatch.setattr(rotation, "seed_credentials", lambda: credentials)
    monkeypatch.setattr(rotation, "usage_probe", lambda credential: dict(probes[credential["label"]]))
    monkeypatch.setattr(rotation, "synchronize_pools", lambda *args: [])
    monkeypatch.setattr(rotation, "write_usage_cache", lambda *args: None)
    monkeypatch.setattr(rotation, "append_log", lambda message: None)
    monkeypatch.setattr(rotation, "load_state", lambda: deepcopy(stored["value"]))

    def save_state(state):
        snapshot = deepcopy(state)
        stored["value"] = snapshot
        saves.append(snapshot)

    monkeypatch.setattr(rotation, "save_state", save_state)
    monkeypatch.setattr(rotation.sys, "argv", ["codex-account-rotation.py"])
    return stored, saves


def _three_probe_set(first):
    return {
        "tabiaadib": first,
        "smaadibusa": {"ok": True, "http": 200, "used_percent": 1, "reset_at": 2_000},
        "aadibsmusa1": {"ok": True, "http": 200, "used_percent": 1, "reset_at": 3_000},
    }


def test_unknown_reset_window_fails_closed_without_smoke(monkeypatch, tmp_path):
    _stored, _saves = _main_fixture(
        monkeypatch,
        tmp_path,
        _three_probe_set({"ok": True, "http": 200, "used_percent": 0, "reset_at": None}),
    )
    smokes = []
    monkeypatch.setattr(rotation, "run_smoke", lambda: smokes.append(True) or (True, "exit=0"))

    result = rotation.main()

    assert result == 1
    assert smokes == []


def test_crash_after_touch_attempt_is_not_retried(monkeypatch, tmp_path):
    stored, _saves = _main_fixture(
        monkeypatch,
        tmp_path,
        _three_probe_set({"ok": True, "http": 200, "used_percent": 0, "reset_at": 1_000}),
    )
    monkeypatch.setattr(rotation, "run_smoke", lambda: (_ for _ in ()).throw(RuntimeError("synthetic crash")))

    first_result = rotation.main()

    assert first_result == 1
    assert stored["value"]["accounts"]["tabiaadib"]["touch_attempted_reset_at"] == 1_000

    smokes = []
    monkeypatch.setattr(rotation, "run_smoke", lambda: smokes.append(True) or (True, "exit=0"))
    second_result = rotation.main()

    assert second_result == 1
    assert smokes == []


def test_timeout_after_touch_attempt_is_not_retried(monkeypatch, tmp_path):
    stored, _saves = _main_fixture(
        monkeypatch,
        tmp_path,
        _three_probe_set({"ok": True, "http": 200, "used_percent": 0, "reset_at": 1_000}),
    )
    smokes = []
    monkeypatch.setattr(rotation, "run_smoke", lambda: smokes.append(True) or (False, "timeout"))

    first_result = rotation.main()
    second_result = rotation.main()

    assert first_result == 1
    assert second_result == 1
    assert smokes == [True]
    assert stored["value"]["accounts"]["tabiaadib"]["touch_attempted_reset_at"] == 1_000


def test_clean_credential_drops_unrecognized_fields():
    result = rotation.clean_credential(
        {
            "id": "synthetic-id",
            "label": "tabiaadib",
            "auth_type": "oauth",
            "source": "device_code",
            "access_token": "synthetic-access",
            "refresh_token": "synthetic-refresh",
            "unrecognized_private_field": "do-not-copy",
        },
        priority=0,
        live_ok=True,
    )

    assert "unrecognized_private_field" not in result
    assert result["access_token"] == "synthetic-access"
    assert result["refresh_token"] == "synthetic-refresh"


def test_clean_credential_drops_endpoints_and_auth_metadata():
    result = rotation.clean_credential(
        {
            "id": "synthetic-id",
            "label": "tabiaadib",
            "auth_type": "api_key",
            "source": "device_code",
            "access_token": "synthetic-access",
            "refresh_token": "synthetic-refresh",
            "base_url": "https://attacker.invalid",
            "inference_base_url": "https://attacker.invalid/inference",
            "portal_base_url": "https://attacker.invalid/portal",
            "client_id": "private-client-id",
            "scope": "private-scope",
            "agent_key": "private-agent-key",
            "secret_fingerprint": "private-fingerprint",
            "token_type": "Bearer",
        },
        priority=0,
        live_ok=True,
    )

    assert result["auth_type"] == "oauth"
    assert not set(result) & {
        "base_url",
        "inference_base_url",
        "portal_base_url",
        "client_id",
        "scope",
        "agent_key",
        "secret_fingerprint",
        "token_type",
    }


def test_malformed_jwt_claims_fail_closed():
    assert rotation.decode_claims("header.!!!!.signature") == {}
    assert rotation.account_header("header.!!!!.signature") is None
    assert rotation.account_header(None) is None


def test_window_rollover_after_success_does_not_send_second_prompt(monkeypatch, tmp_path):
    initial = _three_probe_set(
        {"ok": True, "http": 200, "used_percent": 0, "reset_at": 1_000}
    )
    stored, _saves = _main_fixture(monkeypatch, tmp_path, initial)
    probe_calls = {label: 0 for label in rotation.ORDER}

    def changing_probe(credential):
        label = credential["label"]
        probe_calls[label] += 1
        result = dict(initial[label])
        if label == "tabiaadib" and probe_calls[label] > 1:
            result["reset_at"] = 2_000
        return result

    monkeypatch.setattr(rotation, "usage_probe", changing_probe)
    smokes = []
    monkeypatch.setattr(rotation, "run_smoke", lambda: smokes.append(True) or (True, "exit=0"))

    result = rotation.main()

    assert result == 0
    assert smokes == [True]
    entry = stored["value"]["accounts"]["tabiaadib"]
    assert entry["reset_at"] == 2_000
    assert entry["touched"] is False
    assert entry["touched_reset_at"] == 1_000
    assert stored["value"]["all_touched"] is False


def test_all_confirmed_windows_do_not_smoke(monkeypatch, tmp_path):
    probes = _three_probe_set(
        {"ok": True, "http": 200, "used_percent": 0, "reset_at": 1_000}
    )
    initial_state = {
        "version": 1,
        "active": "aadibsmusa1",
        "accounts": {
            label: {
                "reset_at": probe["reset_at"],
                "touched_reset_at": probe["reset_at"],
                "touch_status": "confirmed",
                "touched": True,
            }
            for label, probe in probes.items()
        },
    }
    stored, _saves = _main_fixture(monkeypatch, tmp_path, probes, initial_state)
    smokes = []
    monkeypatch.setattr(rotation, "run_smoke", lambda: smokes.append(True) or (True, "exit=0"))

    result = rotation.main()

    assert result == 0
    assert smokes == []
    assert stored["value"]["all_touched"] is True


def test_window_identity_rejects_non_numeric_values():
    assert rotation.normalize_reset_at(None) is None
    assert rotation.normalize_reset_at("not-an-epoch") is None
    assert rotation.normalize_reset_at(True) is None
    assert rotation.normalize_reset_at(float("nan")) is None
    assert rotation.normalize_reset_at(1_000) == 1_000


def test_derive_state_does_not_confirm_nonfinite_usage():
    state = rotation.derive_account_state(
        {},
        {"ok": True, "http": 200, "used_percent": math.inf, "reset_at": 1_000},
    )

    assert state["touch_status"] == "untouched"
    assert state["touched"] is False


def test_usage_cache_drops_nonfinite_values(monkeypatch):
    captured = {}
    monkeypatch.setattr(
        rotation,
        "atomic_json",
        lambda path, data, mode=0o600: captured.update({"data": data, "mode": mode}),
    )
    monkeypatch.setattr(rotation, "refresh_agents_blocks", lambda payload: None)
    credentials = {label: {"label": label} for label in rotation.ORDER}
    probes = {
        label: {"ok": True, "http": 200, "used_percent": math.inf, "reset_at": math.inf}
        for label in rotation.ORDER
    }

    assert rotation.write_usage_cache(credentials, probes, rotation.PREFERRED) is True
    account = captured["data"]["accounts"][rotation.PREFERRED]
    assert account["used_percent"] is None
    assert "reset_epoch" not in account


def test_smoke_does_not_inherit_provider_credentials(monkeypatch):
    captured = {}
    monkeypatch.setenv("OPENAI_API_KEY", "PRIVATE_SENTINEL")

    def fake_run(command, **kwargs):
        captured["env"] = kwargs["env"]
        return 0, "ROTATION_OK", "", None

    monkeypatch.setattr(rotation, "_run_bounded", fake_run)

    result = rotation.run_smoke()

    assert result == (True, "exit=0")
    assert captured["env"]["HOME"] == "/home/hermes"
    assert "OPENAI_API_KEY" not in captured["env"]
    assert set(captured["env"]) <= {"HOME", "PATH"}


def test_smoke_rejects_bounded_runner_output_overflow(monkeypatch):
    monkeypatch.setattr(
        rotation,
        "_run_bounded",
        lambda *args, **kwargs: (0, "", "", "output_limit"),
    )

    assert rotation.run_smoke() == (False, "output_limit")


def test_smoke_requires_sentinel_on_stdout(monkeypatch):
    monkeypatch.setattr(
        rotation,
        "_run_bounded",
        lambda *args, **kwargs: (0, "", "diagnostic ROTATION_OK", None),
    )

    assert rotation.run_smoke() == (False, "exit=0")


def test_successful_smoke_with_failed_post_probe_stays_ambiguous(monkeypatch, tmp_path):
    probes = _three_probe_set(
        {"ok": True, "http": 200, "used_percent": 0, "reset_at": 1_000}
    )
    stored, _saves = _main_fixture(monkeypatch, tmp_path, probes)
    probe_calls = {label: 0 for label in rotation.ORDER}

    def changing_probe(credential):
        label = credential["label"]
        probe_calls[label] += 1
        if label == "tabiaadib" and probe_calls[label] > 1:
            return {"ok": False, "http": 503, "used_percent": None, "reset_at": None}
        return dict(probes[label])

    monkeypatch.setattr(rotation, "usage_probe", changing_probe)
    monkeypatch.setattr(rotation, "run_smoke", lambda: (True, "exit=0"))

    result = rotation.main()

    assert result == 1
    entry = stored["value"]["accounts"]["tabiaadib"]
    assert entry["touch_status"] == "ambiguous"
    assert entry["touched"] is False


def test_successful_smoke_reconciliation_failure_is_recorded_without_retry(
    monkeypatch, tmp_path
):
    probes = _three_probe_set(
        {"ok": True, "http": 200, "used_percent": 0, "reset_at": 1_000}
    )
    stored, _saves = _main_fixture(monkeypatch, tmp_path, probes)
    smoke_calls = []
    sync_calls = []

    def sync(*args):
        sync_calls.append(True)
        if len(sync_calls) > 1:
            raise OSError("synthetic pool publication failure")
        return []

    monkeypatch.setattr(rotation, "synchronize_pools", sync)
    monkeypatch.setattr(rotation, "run_smoke", lambda: smoke_calls.append(True) or (True, "exit=0"))

    first_result = rotation.main()
    second_result = rotation.main()

    assert first_result == 1
    assert second_result == 1
    assert smoke_calls == [True]
    assert stored["value"]["accounts"]["tabiaadib"]["touch_status"] == "confirmed"
    assert stored["value"]["reconciliation_pending"] is True


def test_state_rewrite_drops_unrecognized_accounts_and_fields(monkeypatch, tmp_path):
    probes = _three_probe_set(
        {"ok": True, "http": 200, "used_percent": 1, "reset_at": 1_000}
    )
    initial_state = {
        "version": 1,
        "active": "tabiaadib",
        "private_top_level": "PRIVATE_SENTINEL",
        "accounts": {
            "PRIVATE_ACCOUNT": {"secret": "PRIVATE_SENTINEL"},
        },
    }
    stored, _saves = _main_fixture(monkeypatch, tmp_path, probes, initial_state)

    assert rotation.main() == 0

    persisted = stored["value"]
    assert "private_top_level" not in persisted
    assert "PRIVATE_ACCOUNT" not in persisted["accounts"]
    assert set(persisted["accounts"]) == set(rotation.ORDER)
