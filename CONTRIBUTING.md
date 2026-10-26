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

There is no default allowlist or package/ancestor configuration discovery. A reviewer
must explicitly select a trusted file with `--allowlist FILE` (one regex per `- ` line).
Patterns suppress entire original lines in both raw and normalized views. Keep them
narrow: placeholder words must never create an automatic whole-line bypass.

## PR checklist

- [ ] `python3 test_skillvet.py` → ALL PASS
- [ ] New rules have fixtures + README row
- [ ] No new dependencies (hard rule — stdlib only)
- [ ] One PR = one rule/feature
