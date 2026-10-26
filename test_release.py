"""Exercise release preparation against disposable, real Git repositories."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).parent / ".github" / "scripts" / "prepare_release.py"


class TestRelease(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        self.git("init", "-b", "main")
        self.git("config", "user.name", "Release test")
        self.git("config", "user.email", "release@example.invalid")
        (self.repo / "pyproject.toml").write_text(
            '[project]\nname = "skill-vet"\nversion = "0.2.0"\n', encoding="utf-8"
        )
        self.git("add", ".")
        self.git("commit", "-m", "fix: tested change")
        self.source = self.git("rev-parse", "HEAD")
        self.git("tag", "v0.2.0")
        self.git("update-ref", "refs/remotes/origin/main", self.source)

    def git(self, *args):
        return subprocess.check_output(
            ["git", *args], cwd=self.repo, text=True, stderr=subprocess.PIPE
        ).strip()

    def prepare(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), self.source], cwd=self.repo,
            text=True, capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return dict(line.split("=", 1) for line in result.stdout.splitlines())

    def test_bumps_commits_and_tags_only_manifest(self):
        self.assertTrue(SCRIPT.is_file(), "release helper is not implemented")
        self.assertEqual(self.prepare(), {"tag": "v0.2.1", "push": "true"})
        self.assertEqual(self.git("rev-parse", "HEAD^"), self.source)
        self.assertEqual(self.git("rev-parse", "v0.2.1^{}"), self.git("rev-parse", "HEAD"))
        self.assertEqual(self.git("diff", "--name-only", "HEAD^", "HEAD"), "pyproject.toml")
        self.assertIn('version = "0.2.1"', (self.repo / "pyproject.toml").read_text())
        self.assertEqual(self.git("status", "--porcelain"), "")

    def test_version_is_above_all_existing_stable_tags(self):
        self.git("tag", "v0.10.9")
        self.git("tag", "v99.0.0rc1")
        self.assertEqual(self.prepare()["tag"], "v0.10.10")

    def test_stale_ci_does_not_change_anything(self):
        (self.repo / "new.txt").write_text("new main")
        self.git("add", ".")
        self.git("commit", "-m", "newer change")
        newer = self.git("rev-parse", "HEAD")
        self.git("update-ref", "refs/remotes/origin/main", newer)
        self.git("checkout", "--detach", self.source)
        self.assertEqual(self.prepare(), {})
        self.assertEqual(self.git("rev-parse", "HEAD"), self.source)
        self.assertEqual(self.git("tag", "--list"), "v0.2.0")

    def test_rerun_recovers_pushed_release_without_bumping_again(self):
        self.prepare()
        release = self.git("rev-parse", "HEAD")
        self.git("update-ref", "refs/remotes/origin/main", release)
        self.git("checkout", "--detach", self.source)
        self.assertEqual(self.prepare(), {"tag": "v0.2.1", "push": "false"})
        self.assertEqual(self.git("rev-parse", "HEAD"), release)

    def test_release_commit_cannot_start_another_release(self):
        self.prepare()
        self.source = self.git("rev-parse", "HEAD")
        self.git("update-ref", "refs/remotes/origin/main", self.source)
        self.assertEqual(self.prepare(), {})

    def test_atomic_push_publishes_matching_branch_and_tag(self):
        with tempfile.TemporaryDirectory() as remote:
            self.git("init", "--bare", remote)
            self.git("remote", "add", "origin", remote)
            self.git("push", "origin", "HEAD:refs/heads/main")
            tag = self.prepare()["tag"]
            self.git("push", "--atomic", "origin", "HEAD:refs/heads/main", "refs/tags/" + tag)
            self.assertEqual(self.git("--git-dir=" + remote, "rev-parse", "main"),
                             self.git("--git-dir=" + remote, "rev-parse", tag + "^{}"))

    def test_main_race_rejects_both_branch_and_tag(self):
        with tempfile.TemporaryDirectory() as remote:
            self.git("init", "--bare", remote)
            self.git("remote", "add", "origin", remote)
            self.git("push", "origin", "HEAD:refs/heads/main")
            tag = self.prepare()["tag"]
            release = self.git("rev-parse", "HEAD")
            self.git("checkout", "--detach", self.source)
            self.git("commit", "--allow-empty", "-m", "newer main")
            self.git("push", "origin", "HEAD:refs/heads/main")
            self.git("checkout", "--detach", release)
            result = subprocess.run(
                ["git", "push", "--atomic", "origin", "HEAD:refs/heads/main", "refs/tags/" + tag],
                cwd=self.repo, capture_output=True, text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(self.git("--git-dir=" + remote, "tag", "--list", tag), "")
            self.assertNotEqual(self.git("--git-dir=" + remote, "rev-parse", "main"), release)

    def test_dirty_checkout_is_rejected(self):
        (self.repo / "pyproject.toml").write_text("broken")
        result = subprocess.run(
            [sys.executable, str(SCRIPT), self.source], cwd=self.repo,
            text=True, capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.git("rev-parse", "HEAD"), self.source)


if __name__ == "__main__":
    unittest.main()
