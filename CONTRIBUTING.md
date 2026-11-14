# Contributing to GotchU

Thank you for helping. The project is small on purpose, so a few rules keep it that way.

## Set up

Windows 10 or 11 and Python 3.10 or newer. There is nothing to install.

    python -m unittest          # all tests
    python -m gotchu app        # the window

The same checks run on every push and pull request (see `.github/workflows/ci.yml`): lint with ruff,
tests on Python 3.10 to 3.13, a parse check of the PowerShell scripts, and a package install.

## The easiest way to help: the secrets map

`gotchu/secrets_map.json` lists where programs keep passwords, sessions, keys and wallets. Adding a
program is a data change, no code needed. For each entry give the path, the kind, and the programs
that are supposed to read it (`owners`). Only add a location you have checked on a real install.

## Rules for code

1. **Standard library only.** Every dependency is a supply-chain risk for a security tool.
2. **Read-only by default.** Anything that changes the PC is shown first, needs a yes, saves the old
   value, and has an undo.
3. **Few false alarms.** A new detection rule must be run against ordinary software (browsers, Git,
   Steam, Python, an editor) before it is proposed. Say in the pull request what you ran it on.
4. **Never print a secret.** Count it, name its location, nothing more. There is a test for this.
5. **Plain language.** Every message says what was seen, why it matters and what to do, in words a
   non-technical person can follow.
6. **Decision logic is pure.** Collectors gather facts; `analyse()` functions take plain data and return
   findings, so they can be tested with made-up input.
7. **Keep the docs current.** Update README.md, ROADMAP.md and the relevant file in `docs/` in the same
   pull request as the code.

## Tests

Add a test when you add a rule or fix a bug that could come back. Keep tests fast and free of
network access; they run on every push.

## Security problems

Do not open a public issue. See [SECURITY.md](SECURITY.md).
