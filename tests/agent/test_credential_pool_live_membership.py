"""Offline regressions for long-lived pools using synthetic credential stores."""

import json
import time

import pytest

from agent.credential_pool import load_pool
from hermes_cli import auth
# Load the agent facade during collection, before the live-home I/O fixture guards
# the linked worktree's git metadata (the recovery helper late-imports this facade).
import run_agent  # noqa: F401

PROVIDER = "openai-codex"


def _row(cid, priority=0):
    return {
        "id": cid, "label": cid, "priority": priority,
        "auth_type": "oauth", "source": "manual:device_code",
        "access_token": f"offline-access-{cid}",
        "refresh_token": f"offline-refresh-{cid}",
        "expires_at_ms": int((time.time() + 86400) * 1000),
    }


@pytest.fixture
def store(tmp_path, monkeypatch):
    home = tmp_path / "hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr("hermes_constants.get_default_hermes_root", lambda: home)
    monkeypatch.setattr(auth, "_import_codex_cli_tokens", lambda: None)
    path = home / "auth.json"

    def write(rows):
        path.write_text(json.dumps({"version": 1, "credential_pool": {PROVIDER: rows}}))

    return path, write


@pytest.mark.parametrize("existing_spare", [False, True])
def test_existing_pool_rotates_to_account_added_after_load(store, existing_spare):
    path, write = store
    original_rows = [_row("A")] + ([_row("C", 2)] if existing_spare else [])
    write(original_rows)
    pool = load_pool(PROVIDER)
    assert pool.select().id == "A"
    write([*original_rows, _row("B", 1)])

    replacement = pool.mark_exhausted_and_rotate(
        status_code=429, credential_id="A",
        error_context={"reset_at": time.time() + 3600},
    )

    assert replacement is not None
    assert replacement.id == "B"
    assert pool.current() is replacement
    assert {row["id"] for row in json.loads(path.read_text())["credential_pool"][PROVIDER]} == {row["id"] for row in original_rows} | {"B"}


def test_persist_drops_peer_deleted_account_and_adopts_replacement(store):
    path, write = store
    write([_row("R")])
    pool = load_pool(PROVIDER)
    pool.acquire_lease("R")
    write([_row("B", 1)])

    pool._persist()

    assert {row["id"] for row in json.loads(path.read_text())["credential_pool"][PROVIDER]} == {"B"}
    assert [entry.id for entry in pool.entries()] == ["B"]
    assert pool.current() is None
    assert pool._active_leases == {"R": 1}
    pool.release_lease("R")
    assert pool._active_leases == {}


@pytest.mark.parametrize("empty_first", [False, True])
def test_borrowed_root_membership_stays_root_owned_after_peer_addition(store, monkeypatch, empty_first):
    from agent.credential_pool import PooledCredential

    path, write = store
    write([_row("R")])
    profile = path.parent / "profiles" / "borrower"
    profile.mkdir(parents=True)
    monkeypatch.setenv("HERMES_HOME", str(profile))
    pool = load_pool(PROVIDER)
    assert pool._borrowed_root_ids == {"R"}
    if empty_first:
        write([])
        pool._persist()
        assert pool.entries() == []
    write([_row("B")])

    pool._persist()

    assert [entry.id for entry in pool.entries()] == ["B"]
    assert pool._borrowed_root_ids == {"B"}
    assert not (profile / "auth.json").exists()
    pool.add_entry(PooledCredential.from_dict(PROVIDER, _row("C")))
    local_rows = json.loads((profile / "auth.json").read_text())["credential_pool"][PROVIDER]
    assert {row["id"] for row in local_rows} == {"C"}
    assert {row["id"] for row in json.loads(path.read_text())["credential_pool"][PROVIDER]} == {"B"}


def test_local_singleton_grant_is_not_replaced_by_borrowed_root_membership(store, monkeypatch):
    import base64

    path, _ = store
    profile = path.parent / "profiles" / "independent"
    profile.mkdir(parents=True)

    def singleton(tag):
        claims = base64.urlsafe_b64encode(json.dumps({"exp": int(time.time()) + 3600, "sub": tag}).encode()).decode().rstrip("=")
        return {"version": 1, "providers": {PROVIDER: {"tokens": {
            "access_token": f"h.{claims}.s", "refresh_token": f"offline-independent-{tag}",
        }}}}

    path.write_text(json.dumps(singleton("root")))
    root_before = path.read_bytes()
    local_path = profile / "auth.json"
    local_path.write_text(json.dumps(singleton("profile")))
    monkeypatch.setenv("HERMES_HOME", str(profile))
    pool = load_pool(PROVIDER)
    selected = pool.select()
    assert selected is not None
    assert selected.refresh_token == "offline-independent-profile"
    pool._persist()
    assert pool.current().refresh_token == "offline-independent-profile"
    assert pool._borrowed_root_ids == set()
    assert path.read_bytes() == root_before


def test_local_addition_is_not_mistaken_for_peer_deletion(store):
    from agent.credential_pool import PooledCredential

    path, write = store
    write([_row("R")])
    pool = load_pool(PROVIDER)
    write([_row("B", 1)])
    pool.add_entry(PooledCredential.from_dict(PROVIDER, _row("C", 2)))
    pool._persist()
    assert {entry.id for entry in pool.entries()} == {"B", "C"}
    assert {row["id"] for row in json.loads(path.read_text())["credential_pool"][PROVIDER]} == {"B", "C"}
    assert set(pool._persisted_token_pairs) == {"B", "C"}


def test_blank_token_baseline_still_records_membership(store):
    path, write = store
    reference = {"id": "R", "source": "env:OFFLINE_KEY", "auth_type": "api_key"}
    write([reference])
    bases = auth._token_pairs_by_id([reference])
    assert bases == {"R": (None, None)}
    write([])
    written = auth.write_credential_pool(PROVIDER, [reference, _row("C")], token_bases=bases)
    assert {row["id"] for row in written} == {"C"}
    assert {row["id"] for row in json.loads(path.read_text())["credential_pool"][PROVIDER]} == {"C"}


def test_unchanged_hydrated_reference_preserves_live_object_and_secret(store):
    from agent.credential_pool import CredentialPool, PooledCredential

    path, _ = store
    provider = "deepseek"
    live = PooledCredential.from_dict(provider, {
        **_row("A"), "auth_type": "api_key", "source": "env:DEEPSEEK_API_KEY",
        "request_count": 7,
    })
    reference = live.to_dict()
    assert "access_token" not in reference
    path.write_text(json.dumps({"version": 1, "credential_pool": {provider: [reference]}}))
    pool = CredentialPool(provider, [live])
    pool._persisted_token_pairs = auth._token_pairs_by_id([reference])
    pool.acquire_lease("A")
    auth.write_credential_pool(provider, [reference, _row("B", 1)])
    pool._persist()
    assert pool.current() is live
    assert pool.entries()[0] is live
    assert live.runtime_api_key == "offline-access-A"
    assert live.request_count == 7
    assert pool._active_leases == {"A": 1}
    assert {entry.id for entry in pool.entries()} == {"A", "B"}
    rows = json.loads(path.read_text())["credential_pool"][provider]
    assert "access_token" not in next(row for row in rows if row["id"] == "A")


def test_peer_token_rotation_is_adopted_alongside_new_membership(store):
    path, write = store
    write([_row("A")])
    pool = load_pool(PROVIDER)
    pool.acquire_lease("A")
    rotated = {**_row("A"), "access_token": "offline-rotated-A", "refresh_token": "offline-rotated-refresh-A"}
    write([rotated, _row("B", 1)])
    pool._persist()
    assert pool.current().access_token == rotated["access_token"]
    assert pool.current().refresh_token == rotated["refresh_token"]
    assert {entry.id for entry in pool.entries()} == {"A", "B"}
    assert pool._active_leases == {"A": 1}
    assert json.loads(path.read_text())["credential_pool"][PROVIDER][0]["refresh_token"] == rotated["refresh_token"]


def test_true_exhaustion_and_dead_entries_still_stop_rotation(store):
    _, write = store
    write([_row("A")])
    pool = load_pool(PROVIDER)
    pool.acquire_lease("A")
    reset_at = time.time() + 3600
    dead = {**_row("D", 1), "last_status": "dead", "last_status_at": time.time(), "last_error_reason": "invalid_grant"}
    write([_row("A"), dead])
    assert pool.mark_exhausted_and_rotate(
        status_code=429, credential_id="A", error_context={"reset_at": reset_at},
    ) is None
    for _ in range(3):
        assert pool.select() is None
    assert {entry.id: entry.last_status for entry in pool.entries()} == {"A": "exhausted", "D": "dead"}
    assert next(entry for entry in pool.entries() if entry.id == "A").last_error_reset_at == reset_at


def test_agent_recovery_rebinds_credential_without_changing_conversation(store):
    from copy import deepcopy
    from types import MethodType, SimpleNamespace
    from unittest.mock import Mock

    from agent.agent_runtime_helpers import recover_with_credential_pool
    from agent.client_lifecycle import ClientLifecycleMixin

    _, write = store
    write([_row("A")])
    pool = load_pool(PROVIDER)
    pool.acquire_lease("A")
    history = [{"role": "system", "content": "stable cached prompt"}, {"role": "user", "content": "keep my work"}]
    original_history = deepcopy(history)
    agent = SimpleNamespace(
        provider=PROVIDER, model="gpt-5.4", api_mode="codex_responses",
        base_url="https://chatgpt.com/backend-api/codex", api_key="offline-access-A",
        _credential_pool=pool, _credential_pool_entry_id="A",
        _client_kwargs={"api_key": "offline-access-A", "timeout": 123},
        conversation_history=history, reasoning_config={"effort": "high"},
        _replace_primary_openai_client=Mock(), _apply_client_headers_for_base_url=Mock(),
    )
    agent._swap_credential = MethodType(ClientLifecycleMixin._swap_credential, agent)
    agent._reapply_route_client_config = MethodType(ClientLifecycleMixin._reapply_route_client_config, agent)
    write([_row("A"), _row("B", 1)])
    assert recover_with_credential_pool(
        agent, status_code=429, has_retried_429=True,
        error_context={"reason": "usage_limit_reached", "reset_at": time.time() + 3600},
    ) == (True, False)
    assert agent._credential_pool_entry_id == "B"
    assert agent.api_key == "offline-access-B"
    assert agent.provider == PROVIDER
    assert agent.model == "gpt-5.4"
    assert agent.api_mode == "codex_responses"
    assert agent.base_url == "https://chatgpt.com/backend-api/codex"
    assert agent._client_kwargs["timeout"] == 123
    assert agent.reasoning_config == {"effort": "high"}
    assert agent.conversation_history is history
    assert history == original_history
    agent._replace_primary_openai_client.assert_called_once_with(reason="credential_rotation")

