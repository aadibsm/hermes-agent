"""Local, stdlib-only regression suite; never reads or chmods a live Hermes home.

Run: uv run --no-project --python 3.14 python -I -B /absolute/path/to/this_file.py -v
Only root ownership of the temporary policy fixture is simulated. Files, JSON,
symlink handling, ownership matching, and chmod behavior use the real filesystem.
"""
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from contextlib import ExitStack
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "hermes_constants.py"
spec = importlib.util.spec_from_file_location("acl_constants_under_test", SOURCE)
hc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hc)


@unittest.skipUnless(os.name == "posix", "POSIX permission policy")
class SharedHomeACLTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name).resolve()
        self.shared = self.base / "shared"
        self.shared.mkdir(mode=0o750)
        self.shared.chmod(0o750)
        self.etc = self.base / "etc"
        self.etc.mkdir(mode=0o755)
        self.policy_dir = self.etc / "hermes"
        self.policy_dir.mkdir(mode=0o755)
        self.policy = self.policy_dir / "shared-home-acl.json"
        st = self.shared.stat()
        self.document = {"path": str(self.shared), "uid": st.st_uid, "gid": st.st_gid}
        self.write_policy(self.document)
        self.uid_overrides = {}
        trusted = {self.policy, *self.policy.parents}
        real_stat, real_fstat = os.stat, os.fstat

        def policy_stat(path, *args, **kwargs):
            result = real_stat(path, *args, **kwargs)
            if isinstance(path, (str, bytes, os.PathLike)):
                key = Path(os.fsdecode(path))
                if key in trusted:
                    values = list(result)
                    values[4] = self.uid_overrides.get(key, 0)
                    # The outer workspace ancestry is not the subject of the
                    # fixture. The simulated /etc and its children keep REAL modes.
                    if key != self.policy and key not in (self.etc, self.policy_dir):
                        values[0] &= ~0o022
                    result = os.stat_result(values)
            return result

        def policy_fstat(fd):
            result = real_fstat(fd)
            reference = real_stat(self.policy, follow_symlinks=False)
            if (result.st_dev, result.st_ino) == (reference.st_dev, reference.st_ino):
                values = list(result)
                values[4] = self.uid_overrides.get(self.policy, 0)
                result = os.stat_result(values)
            return result

        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.object(hc, "_SHARED_HOME_ACL_POLICY", self.policy, create=True))
        stack.enter_context(patch.object(hc, "_INSTALL_ROOT", self.base / "install"))
        stack.enter_context(patch.object(hc, "get_managed_system", return_value=None))
        stack.enter_context(patch.object(hc, "_container_or_chmod_skipped", return_value=False))
        stack.enter_context(patch.dict(os.environ, {}, clear=True))
        stack.enter_context(patch.object(os, "stat", side_effect=policy_stat))
        stack.enter_context(patch.object(os, "fstat", side_effect=policy_fstat))

    def write_policy(self, document):
        self.policy.write_text(json.dumps(document), encoding="utf-8")
        self.policy.chmod(0o644)

    def mode(self, path):
        return stat.S_IMODE(path.stat().st_mode)

    def test_auth_parent_preserves_exact_operator_managed_root(self):
        with patch.object(os, "chmod", wraps=os.chmod) as chmod:
            hc.secure_parent_dir(self.shared / "auth.json")
        self.assertEqual(self.mode(self.shared), 0o750)
        chmod.assert_not_called()  # Even chmod to the same mode can rewrite ACLs.


    def test_config_policy_preserves_exact_operator_managed_root(self):
        with patch.object(os, "chmod", wraps=os.chmod) as chmod:
            hc.apply_secure_dir_policy(self.shared, home=self.shared)
        self.assertEqual(self.mode(self.shared), 0o750)
        chmod.assert_not_called()

    def test_descendant_still_private(self):
        child = self.shared / "profiles" / "private"
        child.mkdir(parents=True, mode=0o755)
        hc.secure_parent_dir(child / "auth.json")
        self.assertEqual(self.mode(child), 0o700)

    def test_missing_or_malformed_policy_fails_closed(self):
        for raw in ("{", "[]", '{"path": 42}', json.dumps({**self.document, "uid": True}),
                    json.dumps({**self.document, "gid": 999999})):
            with self.subTest(raw=raw):
                self.shared.chmod(0o750)
                self.policy.write_text(raw)
                hc.secure_parent_dir(self.shared / "auth.json")
                self.assertEqual(self.mode(self.shared), 0o700)
        self.policy.unlink()
        self.shared.chmod(0o750)
        hc.secure_parent_dir(self.shared / "auth.json")
        self.assertEqual(self.mode(self.shared), 0o700)

    def test_untrusted_policy_or_ancestry_fails_closed(self):
        for path in (self.policy, self.policy_dir, self.etc):
            for issue in ("owner", "writable"):
                with self.subTest(path=path, issue=issue):
                    self.shared.chmod(0o750)
                    prior = self.mode(path)
                    if issue == "owner": self.uid_overrides[path] = 123
                    else: path.chmod(prior | 0o022)
                    hc.secure_parent_dir(self.shared / "auth.json")
                    self.assertEqual(self.mode(self.shared), 0o700)
                    self.uid_overrides.pop(path, None)
                    path.chmod(prior)

    def test_symlink_policy_fails_closed(self):
        real = self.policy.with_suffix(".real")
        self.policy.rename(real)
        self.policy.symlink_to(real)
        hc.secure_parent_dir(self.shared / "auth.json")
        self.assertEqual(self.mode(self.shared), 0o700)


if __name__ == "__main__":
    unittest.main()
