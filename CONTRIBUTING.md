# Contributing to skill-vet

Thanks for helping make agent skills safer!

## Dev setup

No dependencies. Python 3.8+. That's it.

```bash
git clone https://github.com/ruslanlap/skill-vet
cd skill-vet
python3 test_skillvet.py   # must print ALL PASS
```

## Adding a detection rule

1. Add a `(ID, severity, pattern, message)` tuple to `RULES` in `skillvet.py`.
2. Add a triggering fixture to `examples/malicious-skill/` (or a new fixture in tests).
3. Add the rule to the table in `README.md`.
4. Run `python3 test_skillvet.py` — all tests must pass.
5. Check your pattern against `examples/clean-skill/` — it must stay clean.

## Adding an allowlist entry

Default allowlist entries in `DEFAULT_ALLOWLIST` must match *placeholder* credentials only
(`TEST_TOKEN`, `sk-...`, `your-api-key`). Never allowlist broad patterns like `token` —
that defeats the scanner.

## PR checklist

- [ ] `python3 test_skillvet.py` → ALL PASS
- [ ] New rules have fixtures + README row
- [ ] No new dependencies (hard rule — stdlib only)
- [ ] One PR = one rule/feature
