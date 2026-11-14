# GotchU

[![PyPI](https://img.shields.io/pypi/v/gotchu)](https://pypi.org/project/gotchu/)
[![CI](https://github.com/AnshMittal08/GotchU/actions/workflows/ci.yml/badge.svg)](https://github.com/AnshMittal08/GotchU/actions/workflows/ci.yml)

**Antivirus guards the door. GotchU guards the safe.**

Some malware does not break your PC. It runs once, copies your saved passwords, logins and wallets, and
leaves. Antivirus often misses it, and cleaning up afterwards does not un-steal anything.

GotchU is a free tool for Windows. It warns you before a bad click, catches the thief in the act, and
tells you what to do after.

![One wrong click, with and without GotchU](https://raw.githubusercontent.com/AnshMittal08/GotchU/main/docs/img/theft.svg)

Status: early. It works on the author's Windows 11 Home PC; it has not been tested widely.

## Install

You need Windows 10 or 11 and Python 3.10 or newer. Nothing else.

    pip install gotchu
    gotchu ui

`gotchu ui` opens a local window in your browser. Everything can also be done from the command line.

Have [uv](https://docs.astral.sh/uv/)? Then you can run it without installing: `uvx gotchu ui`

**If Windows blocks the `gotchu` command.** With Smart App Control on, Windows may say "An Application
Control policy has blocked this file", because the command pip makes is not signed. Use
`python -m gotchu ui` instead. It does the same thing. A signed installer is planned.

## What it does

![GotchU commands: before, during and after a bad click](https://raw.githubusercontent.com/AnshMittal08/GotchU/main/docs/img/commands.svg)

| Command | What it tells you or does |
|---|---|
| `gotchu check <file>` | Is this download safe to open? It reads the file without running it. |
| `gotchu harden` | Which Windows protections are off? It can turn them on, and `--undo` puts them back. |
| `gotchu exposure` | What could a thief take from this PC today? Counts only, it never shows a secret. |
| `gotchu tripwire` | Plants decoy files. When one is read you get an alarm, and `--cut` cuts that program's internet. |
| `gotchu vault` | Keeps key files encrypted with a passphrase, so a stolen copy is useless. |
| `gotchu scan` | Am I infected right now? |
| `gotchu respond` | I ran something bad. A checklist of what to do, in order. |
| `gotchu ui` | One local window for all of the above. |
| `gotchu setup` | Installs or removes the small helpers that need administrator rights. |

Every command in detail: [docs/COMMANDS.md](https://github.com/AnshMittal08/GotchU/blob/main/docs/COMMANDS.md)

## Try it

    gotchu check Downloads\game.zip
    gotchu scan
    gotchu exposure
    gotchu tripwire --on
    gotchu vault create

## Promises

- **Local.** Nothing leaves your PC. No account.
- **Read-only unless you say so.** A change needs your yes and a Windows permission prompt, and can be undone.
- **Plain language.** Every finding says what was seen, why it matters and what to do.

## Honest limits

- No tool stops every attack.
- The tripwire raises its alarm for decoys only. Reads of your real login stores are listed for review,
  not yet alarmed.
- A patient attacker with administrator rights can switch any tool off.
- The vault protects files at rest. A file you have taken out is an ordinary file again.
- If you lose both the vault passphrase and the recovery key, the files are gone.
- If GotchU sits in a folder your account can change (a cloned copy, or Python installed just for you),
  a program running as you could change GotchU too. `gotchu setup` tells you when that is the case.

## Learn more

- [How it works](https://github.com/AnshMittal08/GotchU/blob/main/docs/ARCHITECTURE.md): the parts, what
  runs with which rights, and how the tripwire, locks and vault work, as diagrams.
- [Who it is for](https://github.com/AnshMittal08/GotchU/blob/main/docs/USER_FLOWS.md): the journeys it
  is designed around.
- [Where it is going](https://github.com/AnshMittal08/GotchU/blob/main/ROADMAP.md): unlocking the vault
  with Windows Hello, an alarm for reads of real browser and chat stores, and a signed installer.
- [What changed](https://github.com/AnshMittal08/GotchU/blob/main/CHANGELOG.md) in each release.
- [Landing page](https://github.com/AnshMittal08/GotchU/blob/main/site/index.html): one file; download
  it and open it in a browser. Scrolling plays a theft twice in 3D, once unguarded and once with GotchU.

## Help out

Tests: `python -m unittest`. Every push is also linted and tested on Python 3.10 to 3.13 by GitHub Actions.

To help, see [CONTRIBUTING.md](https://github.com/AnshMittal08/GotchU/blob/main/CONTRIBUTING.md).
To report a weakness, see [SECURITY.md](https://github.com/AnshMittal08/GotchU/blob/main/SECURITY.md).

## Licence

Apache-2.0. See [LICENSE](https://github.com/AnshMittal08/GotchU/blob/main/LICENSE).
