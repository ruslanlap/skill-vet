#!/usr/bin/env python3
"""skill-vet — vet AI agent skills before your agent runs them.

Scans SKILL.md skill bundles (scripts, frontmatter, references) for:
prompt injection, data exfiltration, destructive commands, credential
harvesting, and unsafe install scripts. Zero dependencies, stdlib only.

Exit codes: 0 = pass, 1 = findings at or above --fail-on severity.
"""
import argparse, json, os, re, sys
from pathlib import Path

SEV_ORDER = {"info": 0, "warn": 1, "high": 2, "critical": 3}

# (id, severity, pattern, message)
RULES = [
    ("EXFIL-ENV-PIPE", "critical",
     r"^\s*(env|printenv)\s*\|",
     "Pipes a full environment dump into another command — credential exfiltration pattern."),
    ("EXFIL-ENV", "critical",
     r"(curl|wget|fetch|Invoke-WebRequest|httpie)[^\n|;]*\$\{?\(?(env|ENV)\)?[\s\S]{0,80}\|\s*(curl|wget|sh|bash)",
     "Pipes environment variables to a network command — credential exfiltration pattern."),
    ("EXFIL-ENV-CURL", "critical",
     r"https?://[^\s\"']*[\?&=][^\s\"']*\$\(?(env|printenv|ENV)\b",
     "URL embeds environment dump (env/printenv) — exfiltration endpoint."),
    ("NETPIPE-SECRET", "critical",
     r"(curl|wget)[^\n]*(-d|--data|-F|--form|--upload-file)[^\n]*(\$\{?[A-Z_]*(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL))",
     "Sends a key/token/secret variable in an HTTP request body."),
    ("CRED-HARVEST", "high",
     r"\b(cat|type|Get-Content)\s+[^|\n]*(\.ssh/id_|\.aws/credentials|\.netrc|credentials\.json|\.npmrc|\.pypirc|\.git-credentials|\.env\b)",
     "Reads well-known credential files (.ssh, .aws, .netrc, .npmrc, .env...)."),
    ("DESTRUCTIVE", "high",
     r"\brm\s+-rf?\s+(/|~|\$HOME|\.)(\s|$|/)`?",
     "rm -rf on /, ~, $HOME or cwd — destructive filesystem wipe."),
    ("EVAL-OBFUSCATION", "high",
     r"\b(eval|exec)\s*\(\s*base64|base64\s+-d\s*<?\s*\|\s*(sh|bash|zsh|python)",
     "Base64-decoded payload piped into a shell/interpreter — obfuscated execution."),
    ("REVERSE-SHELL", "critical",
     r"(bash|sh|nc|ncat|netcat)\s+-i?\s*>&\s*/dev/tcp/|mkfifo[^\n]*nc\s+-e|/dev/tcp/[^\s]+/\d+\s*0?>&?1",
     "Reverse shell pattern (bash /dev/tcp, nc -e)."),
    ("INJECT-IGNORE-PREVIOUS", "high",
     r"(?i)(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)",
     "Prompt injection: instructs the agent to ignore its instructions."),
    ("INJECT-EXFIL-REQUEST", "high",
     r"(?i)(send|post|upload|forward)\s+(the\s+)?(api[_\s]?key|token|secret|credentials|\.env)[^\n]{0,40}(to|via|at)\s+(https?://|discord|webhook|telegram)",
     "Prompt injection: asks the agent to send secrets to a remote endpoint."),
    ("INJECT-HIDDEN", "medium",
     r"<!--[\s\S]{0,200}?(?i:ignore|exfiltrate|curl|http)[\s\S]{0,200}?-->",
     "Hidden instruction inside HTML comment (invisible to humans, read by agents)."),
    ("UNICODE-STEGO", "medium",
     r"[\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069]",
     "BiDi unicode control chars — can hide or reorder instructions visually."),
    ("INSTALL-PIPE-SHELL", "warn",
     r"curl[^\n]*\|\s*(sudo\s+)?(sh|bash|zsh)\b",
     "curl | sh install pattern — reviews impossible, verify the source."),
    ("TELEMETRY-PHONES-HOME", "warn",
     r"(?i)(telemetry|analytics|beacon|tracking)[^\n]{0,60}(post|send|report|collect)",
     "Skill self-reports telemetry — disclosed or not?"),
    ("KEYCHAIN-ACCESS", "high",
     r"(security\s+find-generic-password|secret-tool\s+lookup|cmdkey\s+/list)",
     "Reads OS keychain / credential manager."),
    ("CLIPBOARD-EXFIL", "high",
     r"(pbpaste|xclip\s+-o|xsel\s+-o|wl-paste|Get-Clipboard)[^\n|;]*\|\s*(curl|wget|nc|ncat)",
     "Pipes clipboard contents to a network command — clipboard exfiltration."),
    ("PERSIST-HOOK", "high",
     r"(crontab|/etc/cron\.|LaunchAgents|\.(?:bashrc|zshrc|bash_profile|profile))[^|\n]*(?:>>|>[^>]|tee\s)|(?:>>|>[^>]|tee\s)[^|\n]*\.(?:bashrc|zshrc|bash_profile|zprofile)",
     "Appends to shell startup files / cron — persistence mechanism."),
    ("OSA-AUTOMATION", "warn",
     r"\bosascript\s+-e",
     "macOS osascript automation — can drive GUI, dialogs and network without prompts."),
]

DEFAULT_ALLOWLIST = [
    # CI/test fixtures legitimately contain fake tokens; do not flag
    (r"TEST[-_]?TOKEN|FAKE[-_]?KEY|DUMMY|EXAMPLE[_-]?KEY|your[-_]?api[-_]?key|ghp_[A-Za-z0-9]{4}\.\.\.|sk-\.\.\.", "placeholder/test credential reference"),
]

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv"}
LEVEL_MAP = {"info": "note", "warn": "warning", "medium": "warning",
             "high": "error", "critical": "error"}
TEXT_SUFFIXES = {".md", ".markdown", ".txt", ".py", ".js", ".ts", ".sh", ".bash", ".zsh",
                 ".ps1", ".yaml", ".yml", ".json", ".toml", ".rb", ".go", ".rs", ".c", ".h",
                 ".cpp", ".cs", ".conf", ".cfg", ".ini", ".example", ""}


def parse_allowlist_file(cfg: Path):
    allow = []
    for line in cfg.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = line.strip()
        if s.startswith("- ") and ":" not in s:
            pat = s[2:].strip().strip('"\'')
            if pat:
                try:
                    allow.append(re.compile(pat))
                except re.error as e:
                    print(f"skill-vet: bad allowlist regex {pat!r}: {e}", file=sys.stderr)
    return allow


def find_allowlist(p: Path):
    """Defaults merged with the nearest .skillvet.yml up the tree from p."""
    allow = [re.compile(p_) for p_, _ in DEFAULT_ALLOWLIST]
    d = p if p.is_dir() else p.parent
    while True:
        for name in (".skillvet.yml", ".skillvet.yaml"):
            cfg = d / name
            if cfg.exists():
                return allow + parse_allowlist_file(cfg)
        if d.parent == d:
            return allow
        d = d.parent


def iter_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            p = Path(dirpath) / fn
            if p.suffix.lower() in TEXT_SUFFIXES or fn.upper() == "SKILL.MD":
                yield p


def scan(root: Path, allow=None):
    if allow is None:
        allow = find_allowlist(root)
    findings = []
    files = iter_files(root) if root.is_dir() else [p for p in [root] if p.suffix.lower() in TEXT_SUFFIXES or p.name.upper() == "SKILL.MD"]
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = f.relative_to(root) if root.is_dir() else f.name
        for lineno, line in enumerate(text.splitlines(), 1):
            for allow_re in allow:
                if allow_re.search(line):
                    break
            else:
                for rid, sev, pat, msg in RULES:
                    if re.search(pat, line):
                        findings.append({
                            "rule": rid, "severity": sev,
                            "file": str(rel), "line": lineno,
                            "message": msg,
                            "snippet": line.strip()[:200],
                        })
    return findings


def to_sarif(findings, root):
    rules = [{"id": r[0], "shortDescription": {"text": r[0]},
              "fullDescription": {"text": r[3]},
              "defaultConfiguration": {"level": LEVEL_MAP[r[1]]}}
             for r in RULES]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "skill-vet", "informationUri":
                  "https://github.com/ruslanlap/skill-vet", "rules": rules}},
                  "results": [{
                      "ruleId": f["rule"],
                      "level": LEVEL_MAP[f["severity"]],
                      "message": {"text": f"{f['message']} `{f['snippet']}`"},
                      "locations": [{"physicalLocation": {"artifactLocation": {
                          "uri": f["file"]}, "region": {"startLine": f["line"]}}}],
                  } for f in findings]}],
    }


def main():
    ap = argparse.ArgumentParser(prog="skill-vet", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path", nargs="*", default=["."], help="skill directories or files (default: .)")
    ap.add_argument("--sarif", metavar="FILE", help="write SARIF 2.1.0 report")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--format", choices=["text", "github"], default="text",
                    help="github = ::error workflow annotations (auto with CI env)")
    ap.add_argument("--fail-on", choices=list(SEV_ORDER), default="high",
                    help="minimum severity to fail CI (default: high)")
    args = ap.parse_args()

    targets = []
    for p in args.path:
        rp = Path(p).resolve()
        if not rp.exists():
            sys.exit(f"skill-vet: {rp} does not exist")
        targets.append(rp)
    findings = []
    for t in targets:
        findings.extend(scan(t))

    if args.sarif:
        Path(args.sarif).write_text(json.dumps(to_sarif(findings, targets[0]), indent=2))
    if args.json:
        print(json.dumps({"findings": findings}, indent=2))
    elif args.format == "github" or os.getenv("GITHUB_ACTIONS") == "true":
        # GitHub Actions workflow annotations — show inline on the PR
        for f in findings:
            print(f"::error file={f['file']},line={f['line']},title={f['rule']}::{f['message']}")
        print(f"::notice::skill-vet: {len(findings)} finding(s)")
    else:
        if not findings:
            names = ", ".join(t.name for t in targets)
            print(f"✅ skill-vet: no issues found in {names}")
        else:
            for f in findings:
                icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "warn": "🟡", "info": "⚪"}[f["severity"]]
                print(f"{icon} [{f['rule']}] {f['file']}:{f['line']} — {f['message']}\n    {f['snippet']}")
            print(f"\n{len(findings)} finding(s)")

    threshold = SEV_ORDER[args.fail_on]
    failed = [f for f in findings if SEV_ORDER[f["severity"]] >= threshold]
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
