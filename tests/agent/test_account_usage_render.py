from datetime import datetime, timedelta, timezone

import pytest

from agent import account_usage


@pytest.mark.parametrize("markdown", [False, True])
def test_elapsed_reset_does_not_claim_quota_has_reset(monkeypatch, markdown):
    now = datetime(2026, 10, 14, 1, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(account_usage, "_utc_now", lambda: now)
    snapshot = account_usage.AccountUsageSnapshot(
        provider="openai-codex", source="usage_api", fetched_at=now - timedelta(minutes=10),
        windows=(account_usage.AccountUsageWindow("Session", used_percent=100, reset_at=now - timedelta(minutes=1)),),
    )

    line = next(line for line in account_usage.render_account_usage_lines(snapshot, markdown=markdown) if line.startswith("Session:"))

    assert "0% remaining (100% used)" in line
    assert "reset time passed" in line
    assert "/usage" in line and "confirm" in line
    assert "resets now" not in line


@pytest.mark.parametrize("seconds, expected", [(0.1, "<1m"), (30, "<1m"), (59, "<1m"), (60, "1m"), (3660, "1h 1m"), (90000, "1d 1h")])
def test_future_reset_countdown_preserves_positive_time(monkeypatch, seconds, expected):
    now = datetime(2026, 10, 14, 1, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(account_usage, "_utc_now", lambda: now)
    snapshot = account_usage.AccountUsageSnapshot(
        provider="anthropic", source="oauth_usage_api", fetched_at=now,
        windows=(account_usage.AccountUsageWindow("Current session", used_percent=95, reset_at=now + timedelta(seconds=seconds)),),
    )

    line = next(line for line in account_usage.render_account_usage_lines(snapshot) if line.startswith("Current session:"))

    assert f"resets in {expected}" in line
    assert "in 0m" not in line
