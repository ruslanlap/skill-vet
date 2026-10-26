"""Prepare a patch release locally; only the workflow may push or publish it."""
from pathlib import Path
import re
import subprocess
import sys


def git(*args):
    return subprocess.check_output(["git", *args], text=True).strip()


def prepare(source):
    # Never fold unrelated local changes into a privileged release commit.
    subprocess.run(["git", "diff", "--exit-code"], check=True)
    subprocess.run(["git", "diff", "--cached", "--exit-code"], check=True)
    if git("rev-parse", "HEAD") != source:
        raise ValueError("checkout must match the tested CI SHA")
    main = git("rev-parse", "origin/main")
    subject = git("log", "-1", "--format=%s", main)
    release = re.fullmatch(r"chore\(release\): (v[0-9]+\.[0-9]+\.[0-9]+)", subject)
    if main != source:
        # A failed publish can be retried after the atomic commit+tag push.
        if (release and git("rev-parse", main + "^") == source
                and git("rev-parse", release[1] + "^{}") == main
                and git("diff", "--name-only", source, main) == "pyproject.toml"):
            git("checkout", "--detach", main)
            return release[1], "false"
        print("Main advanced; skipping stale CI run.", file=sys.stderr)
        return None
    if release:
        print("Release commit; skipping to prevent a loop.", file=sys.stderr)
        return None

    manifest = Path("pyproject.toml")
    text = manifest.read_text(encoding="utf-8")
    pattern = r'(?m)^version = "([0-9]+\.[0-9]+\.[0-9]+)"$'
    versions = re.findall(pattern, text)
    if len(versions) != 1:
        raise ValueError("expected exactly one stable manifest version")
    versions += re.findall(r"(?m)^v([0-9]+\.[0-9]+\.[0-9]+)$", git("tag", "--list"))
    major, minor, patch = max(tuple(map(int, version.split("."))) for version in versions)
    version = "{}.{}.{}".format(major, minor, patch + 1)
    tag = "v" + version
    manifest.write_text(re.sub(pattern, 'version = "' + version + '"', text), encoding="utf-8")
    git("add", "--", "pyproject.toml")
    git("commit", "-m", "chore(release): " + tag)
    git("tag", "-a", tag, "-m", "Release " + tag)
    return tag, "true"


if __name__ == "__main__":
    result = prepare(sys.argv[1])
    if result:
        print("tag=" + result[0])
        print("push=" + result[1])
