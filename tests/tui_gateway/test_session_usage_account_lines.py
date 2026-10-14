"""Both the Desktop usage feed and typed ``/usage`` refresh provider account limits.

The renderer dispatches typed slash commands through ``slash.exec``, not ``session.usage``;
both paths must reuse the account-limit fetch/render helper for the owning live route.
"""
from datetime import datetime, timedelta, timezone
import threading
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from agent.account_usage import AccountUsageSnapshot, AccountUsageWindow


def _codex_snapshot() -> AccountUsageSnapshot:
    return AccountUsageSnapshot(
        provider="openai-codex", source="usage_api", fetched_at=datetime.now(timezone.utc), plan="Plus",
        windows=(AccountUsageWindow(label="Weekly", used_percent=12.0),),
    )


def test_session_usage_rpc_ships_account_lines_for_the_live_route():
    from tui_gateway import server

    agent = SimpleNamespace(provider="openai-codex", base_url="https://chatgpt.example/backend-api",
                            api_key="tok", model="gpt-5.3-codex")
    session = {"agent": agent, "history": [], "running": False, "session_key": "sess-usage"}
    sid = "sid-usage-account"
    server._sessions[sid] = session
    seen: list[tuple] = []

    def _fetch(provider, *, base_url=None, api_key=None):
        seen.append((provider, base_url, api_key))
        return _codex_snapshot()

    try:
        with (
            patch.object(server, "_get_usage", return_value={"calls": 1, "input": 10, "output": 20, "total": 30}),
            patch("agent.account_usage.fetch_account_usage", _fetch),
            patch("agent.account_usage.nous_credits_lines", lambda **kw: []),
        ):
            r = server._methods["session.usage"]("r1", {"session_id": sid})
    finally:
        server._sessions.pop(sid, None)

    assert "error" not in r, r
    result = r["result"]
    assert result["total"] == 30 and "credits_lines" not in result
    # Fetched against the session's own route, not a default endpoint.
    assert seen == [("openai-codex", "https://chatgpt.example/backend-api", "tok")]
    assert result["account_lines"]


@pytest.mark.parametrize("arg", ["reset", "reset --force", "nonsense", "help"])
@pytest.mark.parametrize("active", [True, False])
def test_slash_usage_arguments_are_explicit_and_never_redeem(monkeypatch, arg, active):
    from tui_gateway import server

    sid = "sid-usage-arguments"
    session = {"agent": SimpleNamespace(model="fixture-model") if active else None,
               "history": [], "history_lock": threading.RLock(),
               "running": True, "session_key": "durable-usage-arguments"}
    monkeypatch.setitem(server._sessions, sid, session)
    with (
        patch.object(server, "_session_usage_snapshot", return_value={}),
        patch("agent.account_usage.fetch_account_usage") as fetch,
        patch("agent.account_usage.redeem_codex_reset_credit") as redeem,
        patch.object(server, "_SlashWorker") as worker,
    ):
        response = server._methods["slash.exec"]("r", {"session_id": sid, "command": f"/usage {arg}"})
        assert "error" not in response, response
        output = response["result"]["output"]
        assert "/usage — refresh" in output
        assert "/usage help" in output
        assert "reset is not supported" in output
        if arg == "nonsense":
            assert "Unsupported /usage argument: nonsense" in output
        assert "Session Token Usage" not in output
        fetch.assert_not_called()
        redeem.assert_not_called()
        worker.assert_not_called()
    assert server._sessions[sid] is session
    assert session["running"] is True


def test_slash_usage_refetches_account_limits_without_replacing_the_session(monkeypatch):
    from tui_gateway import server

    sid = "sid-slash-usage"
    agent = SimpleNamespace(provider="openai-codex", base_url="https://fixture.invalid/backend-api",
                            api_key="fixture-token", model="fixture-model")
    history = [{"role": "user", "content": "existing conversation"}]
    session = {"agent": agent, "history": history, "history_lock": threading.RLock(),
               "running": True, "session_key": "durable-slash-usage"}
    monkeypatch.setitem(server._sessions, sid, session)
    now = datetime.now(timezone.utc)
    snapshots = [
        AccountUsageSnapshot(provider="openai-codex", source="test", fetched_at=now,
                             windows=(AccountUsageWindow(label="Session", used_percent=percent,
                                                         reset_at=now - timedelta(seconds=1)),))
        for percent in (100, 5)
    ]
    with (
        patch.object(server, "_session_usage_snapshot",
                     return_value={"calls": 1, "input": 10, "output": 20, "total": 30}),
        patch("agent.account_usage.fetch_account_usage", side_effect=snapshots) as fetch,
        patch.object(server, "_SlashWorker") as worker,
    ):
        first = server._methods["slash.exec"]("r1", {"session_id": sid, "command": "usage"})
        assert "error" not in first, first
        fetch.assert_called_once_with("openai-codex", base_url=agent.base_url, api_key=agent.api_key)
        first_output = first["result"]["output"]
        assert "Session Token Usage" in first_output and "30" in first_output
        assert "100% used" in first_output and "reset time passed" in first_output
        second = server._methods["slash.exec"]("r2", {"session_id": sid, "command": "/usage"})
        assert "error" not in second, second
        assert fetch.call_count == 2
        assert "5% used" in second["result"]["output"]
        assert "100% used" not in second["result"]["output"]
        worker.assert_not_called()
    assert server._sessions[sid] is session
    assert session["agent"] is agent and session["history"] is history
    assert session["session_key"] == "durable-slash-usage" and session["running"] is True


def test_usage_banked_credit_count_has_no_unsupported_reset_cta(monkeypatch):
    from agent import account_usage
    from tui_gateway import server

    sid = "sid-banked-usage"
    agent = SimpleNamespace(provider="openai-codex", base_url="https://fixture.invalid/backend-api",
                            api_key="fixture-token", model="fixture-model")
    monkeypatch.setitem(server._sessions, sid, {
        "agent": agent, "history": [], "history_lock": threading.RLock(),
        "running": True, "session_key": "durable-banked-usage",
    })
    payload = {"rate_limit_reset_credits": {"available_count": 3},
               "rate_limit": {"primary_window": {"used_percent": 100}},
               "credits": {"has_credits": True, "balance": 7.5}}
    with (
        patch.object(server, "_session_usage_snapshot", return_value={"total": 30}),
        patch.object(account_usage, "_resolve_codex_usage_credentials",
                     return_value=("fixture-token", agent.base_url, None)),
        patch.object(account_usage, "_get_json", return_value=payload) as get,
        patch.object(account_usage, "redeem_codex_reset_credit") as redeem,
        patch.object(account_usage.httpx, "Client") as client,
        patch.object(account_usage, "nous_credits_lines", return_value=[]),
        patch.object(server, "_SlashWorker") as worker,
    ):
        snapshot = account_usage.fetch_account_usage("openai-codex", base_url=agent.base_url, api_key=agent.api_key)
        # CLI/Gateway retain their working reset affordance by default, in both render modes.
        for markdown in (False, True):
            assert "use /usage reset to activate" in "\n".join(
                account_usage.render_account_usage_lines(snapshot, markdown=markdown))
        from hermes_cli.subcommands.usage import usage_snapshot_document
        assert usage_snapshot_document(snapshot)["details"] == [
            "You have 3 resets banked - use /usage reset to activate", "Credits balance: $7.50",
        ]
        response = server._methods["slash.exec"]("r", {"session_id": sid, "command": "/usage"})
        assert "error" not in response, response
        feed = server._methods["session.usage"]("feed", {"session_id": sid})
        assert "error" not in feed, feed
        for output in (response["result"]["output"], "\n".join(feed["result"]["account_lines"])):
            assert "3 resets banked" in output
            assert "100% used" in output
            assert "Credits balance: $7.50" in output
            assert "use /usage reset" not in output
            assert "reset redemption is not supported" in output
        assert get.call_count == 3
        redeem.assert_not_called()
        client.assert_not_called()
        worker.assert_not_called()


def test_slash_usage_keeps_profile_scope_and_token_output_on_fetch_failure(tmp_path, monkeypatch):
    import os

    from agent.secret_scope import get_secret, is_multiplex_active, set_multiplex_active
    from hermes_constants import get_hermes_home
    from tui_gateway import server

    homes = [tmp_path / name for name in ("profile-a", "profile-b")]
    for home in homes:
        home.mkdir()
        (home / ".env").write_text(f"USAGE_SCOPE_FIXTURE={home.name}\n", encoding="utf-8")
        agent = SimpleNamespace(provider="openai-codex", base_url=f"https://{home.name}.invalid",
                                api_key=f"fixture-{home.name}", model="fixture-model")
        monkeypatch.setitem(server._sessions, home.name, {
            "profile_home": str(home), "session_key": f"durable-{home.name}", "agent": agent,
            "history": [], "history_lock": threading.RLock(), "running": False,
        })
    monkeypatch.setenv("USAGE_SCOPE_FIXTURE", "launch-profile-must-not-leak")
    before_env = dict(os.environ)
    before_home = get_hermes_home()
    seen = []

    def fetch(provider, *, base_url=None, api_key=None):
        home = get_hermes_home()
        seen.append((home, get_secret("USAGE_SCOPE_FIXTURE"), provider, base_url, api_key))
        if home == homes[1]:
            raise RuntimeError("provider temporarily unavailable")
        return _codex_snapshot()

    previous = is_multiplex_active()
    set_multiplex_active(True)
    try:
        with (
            patch.object(server, "_session_usage_snapshot", return_value={"total": 30}),
            patch("agent.account_usage.fetch_account_usage", fetch),
        ):
            for home in (homes[0], homes[1], homes[0]):
                response = server._methods["slash.exec"]("r", {"session_id": home.name, "command": "usage"})
                assert "error" not in response, response
                output = response["result"]["output"]
                assert "Session Token Usage" in output and "30" in output
                assert ("12% used" in output) == (home == homes[0])
                assert get_hermes_home() == before_home
                assert dict(os.environ) == before_env
    finally:
        set_multiplex_active(previous)
    assert seen == [
        (home, home.name, "openai-codex", f"https://{home.name}.invalid", f"fixture-{home.name}")
        for home in (homes[0], homes[1], homes[0])
    ]
