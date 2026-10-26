#!/usr/bin/env python3
"""skill-vet — vet AI agent skills before your agent runs them.

Scans SKILL.md skill bundles (scripts, frontmatter, references) for:
prompt injection, data exfiltration, destructive commands, credential
harvesting, and unsafe install scripts. Zero dependencies, stdlib only.

Exit codes: 0 = pass, 1 = findings at or above --fail-on severity.
"""
import argparse, json, os, re, sys, unicodedata
from pathlib import Path

SEV_ORDER = {"info": 0, "warn": 1, "medium": 2, "high": 3, "critical": 4}

SECRET = r"(?:api[_\s]?keys?|tokens?|secrets?|credentials?|passwords?|documents?|private\s+keys?|cookies?|\.env|парол\w*|документ\w*|приватн\w*\s+ключ\w*|кукі)"
SEND = r"(?:send|post|upload|forward|exfiltrate|надішли|надсилай|відправ\w*|завантаж\w*)"
DEST = r"(?:https?://|discord|webhook|telegram|телеграм)"
INVISIBLES = r"[\u200b\u2060\ufeff\u202a-\u202e\u2066-\u2069\U000e0001\U000e0020-\U000e007f]"

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
    ("DECODE-EXEC", "high",
     # sink-first (os.system(base64.b64decode(x))) AND decode-first (x = b64decode(...); exec(x))
     r"(?:os\.system|subprocess\.(?:run|call|Popen|check_output)|exec\s*\(|Function\s*\()\s*\(?\s*[\w.]*\s*\(?\s*"
     r"(?:b64decode|decodebytes|fromhex|codecs\.decode|zlib\.decompress|gzip\.decompress)"
     r"|(?:b64decode|decodebytes|fromhex|codecs\.decode|zlib\.decompress|gzip\.decompress)[^\n]{0,60}?"
     r"(?:os\.system|subprocess\.(?:run|call|Popen|check_output)|exec\s*\(|Function\s*\()",
     "Runtime-decoded payload handed straight to an execution sink (no eval/exec literal needed)."),
    ("REVERSE-SHELL", "critical",
     r"(bash|sh|nc|ncat|netcat)\s+-i?\s*>&\s*/dev/tcp/|mkfifo[^\n]*nc\s+-e|/dev/tcp/[^\s]+/\d+\s*0?>&?1",
     "Reverse shell pattern (bash /dev/tcp, nc -e)."),
    ("INJECT-IGNORE-PREVIOUS", "high",
     r"(?i)(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)",
     "Prompt injection: instructs the agent to ignore its instructions."),
    ("INJECT-EXFIL-REQUEST", "high",
     rf"(?i)(?:\b{SEND}\b[\s\S]{{0,160}}?{SECRET}[\s\S]{{0,160}}?{DEST}|"
     rf"{SECRET}[\s\S]{{0,120}}?\b{SEND}\b[\s\S]{{0,120}}?{DEST})",
     "Prompt injection: asks the agent to send secrets to a remote endpoint."),
    ("INJECT-MEMORY-WRITE", "high",
     r"(?i)\b(write|append|update|overwrite|modify|edit|запиши|додай|зміни)\b[\s\S]{0,120}?"
     r"(?:MEMORY\.md|AGENTS\.md|SOUL\.md|USER\.md|CLAUDE\.md|(?:[\w./~-]*config)\.(?:yaml|yml|json|toml))\b",
     "Prompt injection: asks to write agent memory, instructions or configuration."),
    ("INJECT-SAFETY-DISABLE", "high",
     r"(?i)\b(disable|bypass|turn\s+off|вимкни|обійди)\b[\s\S]{0,60}?"
     r"(?:safety\s+(?:checks?|filters?|rules?|guards?)|security\s+(?:checks?|filters?)|safeguards?|перевір\w*\s+безпеки)",
     "Prompt injection: asks to disable safety or security checks."),
    ("INJECT-HIDDEN", "medium",
     r"<!--[\s\S]{0,400}?(?i:ignore|exfiltrate|curl|http)[\s\S]{0,100}?(?:-->|$)",
     "Hidden instruction inside HTML comment (invisible to humans, read by agents)."),
    ("UNICODE-STEGO", "medium",
     INVISIBLES,
     "Invisible Unicode / BiDi / tag characters can conceal instructions."),
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
        if s.startswith("- "):
            pat = s[2:].strip().strip('"\'')
            if pat:
                try:
                    allow.append(re.compile(pat))
                except re.error as e:
                    print(f"skill-vet: bad allowlist regex {pat!r}: {e}", file=sys.stderr)
    return allow


def normalized_line(line):
    line = "".join(chr(ord(c) - 0xE0000) if 0xE0020 <= ord(c) <= 0xE007E else c
                   for c in line)
    return unicodedata.normalize("NFKC", re.sub(INVISIBLES, "", line))


def positive_matches(pattern, text):
    # ponytail: bounded EN/UA clause heuristics, not semantics; use a parser if coverage demands it.
    for clause in re.finditer(r"[^;!?]+", text):
        body = clause.group()
        for match in re.finditer(pattern, body):
            prefix = body[:match.start()]
            if re.search(r"(?i)\b(?:never|do\s+not|don't|must\s+not|should\s+not|ніколи\s+не|не)\s+$", prefix):
                continue
            yield clause.start() + match.start()


def iter_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            p = Path(dirpath) / fn
            if p.suffix.lower() in TEXT_SUFFIXES or fn.upper() == "SKILL.MD":
                yield p


def scan(root: Path, allow=None):
    # Suppression is a caller-owned trust decision, never package-controlled discovery.
    allow = [] if allow is None else allow
    findings = []
    files = iter_files(root) if root.is_dir() else [p for p in [root] if p.suffix.lower() in TEXT_SUFFIXES or p.name.upper() == "SKILL.MD"]
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = f.relative_to(root) if root.is_dir() else f.name
        lines = text.splitlines()
        suppressed = [any(p.search(line) for p in allow) for line in lines]
        seen = set()
        for view in (lines, [normalized_line(line) for line in lines]):
            for i, line in enumerate(view):
                if suppressed[i]:
                    continue
                # ponytail: prose gets only 3 lines / 512 chars; code signatures stay line-local.
                window = "\n".join("" if suppressed[j] else view[j]
                                   for j in range(i, min(i + 3, len(view))))[:512]
                for rid, sev, pat, msg in RULES:
                    prose = rid.startswith("INJECT-")
                    candidate = window if prose else line
                    matches = positive_matches(pat, candidate) if prose and rid != "INJECT-HIDDEN" else (
                        m.start() for m in re.finditer(pat, candidate))
                    for start in matches:
                        if start > len(line) or (rid, i) in seen:
                            continue
                        seen.add((rid, i))
                        findings.append({
                            "rule": rid, "severity": sev,
                            "file": str(rel), "line": i + 1,
                            "message": msg, "snippet": lines[i].strip()[:200],
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
    ap.add_argument("--format", choices=["text", "github"], default=None,
                    help="github = ::error workflow annotations (default: auto with CI env)")
    ap.add_argument("--fail-on", choices=list(SEV_ORDER), default="high",
                    help="minimum severity to fail CI (default: high)")
    ap.add_argument("--allowlist", metavar="FILE",
                    help="explicit trusted regex allowlist (never auto-discovered)")
    args = ap.parse_args()
    try:
        allow = parse_allowlist_file(Path(args.allowlist)) if args.allowlist else []
    except OSError as e:
        ap.error(f"cannot read allowlist: {e}")

    targets = []
    for p in args.path:
        rp = Path(p).resolve()
        if not rp.exists():
            sys.exit(f"skill-vet: {rp} does not exist")
        targets.append(rp)
    findings = []
    for t in targets:
        findings.extend(scan(t, allow=allow))

    fmt = args.format or ("github" if os.getenv("GITHUB_ACTIONS") == "true" else "text")
    if args.sarif:
        Path(args.sarif).write_text(json.dumps(to_sarif(findings, targets[0]), indent=2))
    if args.json:
        print(json.dumps({"findings": findings}, indent=2))
    elif fmt == "github":
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
