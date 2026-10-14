"""Dependency-free regression tests for the local gateway cron profile selector.

Run from Documents (isolated mode avoids this snapshot's inspect.py shadowing
stdlib inspect):
    uv run --no-project --offline --no-python-downloads python -I -B \
        fleet-recovery/test_standalone_cron.py -v

AST slices execute the real selector and profile/home resolution helpers without
booting a gateway, loading credentials, importing the incomplete snapshot, or
writing profile data. Only config/directory discovery boundaries are fixtures.
"""

import ast
import logging
import os
from pathlib import Path
import re
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parent
if not (ROOT / "gateway" / "run.py").is_file():
    ROOT = ROOT.parent


def load_functions(relative_path, names, **fixtures):
    """Load only the named production functions, not module startup side effects."""
    source_path = ROOT / relative_path
    tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
    nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef)
             and node.name in names]
    if {node.name for node in nodes} != set(names):
        raise AssertionError(f"Missing AST functions in {relative_path}: {names}")
    future = ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0)
    sliced = ast.fix_missing_locations(ast.Module(body=[future, *nodes], type_ignores=[]))
    module = ModuleType(relative_path.replace("/", ".").removesuffix(".py"))
    module.__dict__.update(fixtures)
    exec(compile(sliced, str(source_path), "exec"), module.__dict__)
    return module


class StandaloneCronTests(unittest.TestCase):
    def setUp(self):
        self.native_root = Path("/__cron_test__/user/.hermes")
        self.active_home = self.native_root / "profiles" / "worker"
        self.addCleanup(patch.stopall)
        patch.dict(os.environ, {"HOME": str(self.native_root.parent),
                                "HERMES_HOME": str(self.active_home)}, clear=True).start()
        self.constants = load_functions(
            "hermes_constants.py",
            {"get_hermes_home", "get_process_hermes_home", "_expand_hermes_home",
             "_get_platform_default_hermes_home", "get_default_hermes_root"},
            Path=Path, os=os, sys=sys, _default_hermes_root_memo=None,
            get_hermes_home_override=lambda: None,
            _warn_profile_fallback_once=Mock(),
        )
        self.standalone = True
        self.enumerate_profiles = Mock(return_value=[
            self.active_home, self.native_root / "profiles" / "disabled_foreign",
        ])
        self.profiles = load_functions(
            "hermes_cli/profiles.py",
            {"profiles_to_serve", "get_active_profile_name", "get_profile_dir",
             "normalize_profile_name", "_get_profiles_root", "_get_default_hermes_home"},
            Path=Path, _PROFILE_ID_RE=re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$"),
            _parked_default_warned=set(), logger=logging.getLogger(__name__),
            profile_is_parked=Mock(return_value=False),
            profile_is_standalone=Mock(side_effect=lambda home:
                                       self.standalone and home == self.active_home),
            _iter_named_profile_dirs=self.enumerate_profiles,
        )
        self.profiles.profiles_to_serve = Mock(wraps=self.profiles.profiles_to_serve)
        package = ModuleType("hermes_cli")
        package.__path__ = []
        package.profiles = self.profiles
        patch.dict(sys.modules, {"hermes_constants": self.constants,
                                 "hermes_cli": package,
                                 "hermes_cli.profiles": self.profiles}).start()
        self.gateway = load_functions(
            "gateway/run.py", {"_cron_tick_profile_homes", "_multiplex_profile_homes"},
            Path=Path,
        )
        self.gateway._multiplex_profile_homes = Mock(
            wraps=self.gateway._multiplex_profile_homes)
        self.config = SimpleNamespace(multiplex_profiles=False)

    def test_standalone_ticks_only_its_active_profile(self):
        self.assertEqual(self.gateway._cron_tick_profile_homes(self.config),
                         [("worker", self.active_home)])
        self.gateway._multiplex_profile_homes.assert_not_called()
        self.enumerate_profiles.assert_not_called()
        self.profiles.profiles_to_serve.assert_called_once_with(multiplex=False)
        self.profiles.profile_is_standalone.assert_called_once_with(self.active_home)


    def test_nonstandalone_behavior_unchanged(self):
        self.standalone = False
        for multiplex in (False, True):
            with self.subTest(multiplex=multiplex):
                self.config.multiplex_profiles = multiplex
                homes = self.gateway._cron_tick_profile_homes(self.config)
                self.assertEqual([name for name, _ in homes],
                                 ["default", "worker", "disabled_foreign"])

    def test_standalone_custom_home_not_enumerated(self):
        self.active_home = Path("/__cron_test__/separate/isolated-home")
        os.environ["HERMES_HOME"] = str(self.active_home)
        os.environ["HERMES_PROFILE"] = "worker"
        self.assertEqual(self.gateway._cron_tick_profile_homes(self.config),
                         [("default", self.active_home)])
        self.enumerate_profiles.assert_not_called()

    def test_default_standalone_ticks_only_default(self):
        self.active_home = self.native_root
        os.environ["HERMES_HOME"] = str(self.native_root)
        self.assertEqual(self.gateway._cron_tick_profile_homes(self.config),
                         [("default", self.native_root)])
        self.enumerate_profiles.assert_not_called()


if __name__ == "__main__":
    unittest.main()
