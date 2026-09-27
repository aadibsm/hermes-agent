"""Opt-in Codex broker route must never leak into local OAuth on partial config."""
import pytest
from agent import codex_broker_route as route_module


def test_broker_route_is_off_only_when_both_settings_absent(monkeypatch):
    values = {}
    monkeypatch.setattr(route_module, 'get_secret', lambda name, default='': values.get(name, default))
    assert route_module.codex_broker_route() is None
    values['HERMES_CODEX_BROKER_KEY'] = 'k' * 40
    with pytest.raises(ValueError, match='without URL'):
        route_module.codex_broker_route()
    values['HERMES_CODEX_BROKER_URL'] = 'http://127.0.0.1:8646/v1'
    assert route_module.codex_broker_route() == (values['HERMES_CODEX_BROKER_URL'], values['HERMES_CODEX_BROKER_KEY'])
    del values['HERMES_CODEX_BROKER_KEY']
    with pytest.raises(ValueError, match='KEY'):
        route_module.codex_broker_route()


def test_broker_route_rejects_non_loopback(monkeypatch):
    values = {'HERMES_CODEX_BROKER_KEY': 'k' * 40,
              'HERMES_CODEX_BROKER_URL': 'http://127.0.0.1.evil.test:8646/v1'}
    monkeypatch.setattr(route_module, 'get_secret', lambda name, default='': values.get(name, default))
    with pytest.raises(ValueError, match='127.0.0.1'):
        route_module.codex_broker_route()
