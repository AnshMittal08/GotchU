# GotchU

[![CI](https://github.com/AnshMittal08/GotchU/actions/workflows/ci.yml/badge.svg)](https://github.com/AnshMittal08/GotchU/actions/workflows/ci.yml)

Antivirus guards the door. GotchU guards the safe.

Password-stealing malware does not need to break Windows. It runs once, copies your saved passwords,
signed-in sessions, chat logins, keys and wallets, and leaves. Antivirus often misses it, and removing
it afterwards does not un-steal anything.

GotchU is a free, local tool for Windows that works on that problem from both sides: it has your back,
and it catches the thief.

Status: early. It works on the author's Windows 11 Home PC; it has not been tested widely.

## What it does today

| Command | Question it answers |
|---|---|
| `gotchu check <file>` | Is this download safe to open? Reads it without running it and looks for the packaging tricks malware uses. |
| `gotchu scan` | Am I infected right now? Looks at running programs and what starts with Windows. |
| `gotchu exposure` | What could a thief take from this PC today? Counts saved passwords, sessions, keys and wallets. Never shows or copies one. |
| `gotchu harden` | Which Windows protections are off? Turns four of them on, saving the old setting so `--undo` is exact. |
| `gotchu tripwire` | Plants decoy wallet files no honest program opens. When one is read you get an alarm, and with `--cut` that program loses its internet. |
| `gotchu vault` | Keeps key files encrypted with a passphrase, so a stolen copy is useless. `vault use` hands a key to one command and removes it afterwards. |
| `gotchu ui` | A local window for check, scan, exposure and harden. |

## Run it

Needs Windows 10 or 11 and Python 3.10 or newer. No other packages.

    python -m gotchu ui
    python -m gotchu exposure
    python -m gotchu tripwire --on
    python -m gotchu vault create
    python -m gotchu vault add --move my-server-key.pem
    python -m gotchu vault use my-server-key.pem -- ssh -i {} user@host

Or install it and use the short command:

    python -m pip install .
    gotchu ui

Tests: `python -m unittest`. Every push is also linted and tested on Python 3.10 to 3.13 by GitHub Actions.

To help, see [CONTRIBUTING.md](CONTRIBUTING.md). To report a weakness, see [SECURITY.md](SECURITY.md).

## Promises

- **Local.** Nothing leaves your PC. No account.
- **Read-only unless you say so.** A change needs your yes and a Windows permission prompt, and can be undone.
- **Plain language.** Every finding says what was seen, why it matters and what to do.
- **Honest limits.** No tool stops every attack. The tripwire catches a thief that sweeps for wallets, not
  every thief; a patient attacker with administrator rights can switch any tool off. The vault protects
  files at rest: a file you have taken out is an ordinary file again, and if you lose both the passphrase
  and the recovery key, the files are gone.

## Where it is going

See [ROADMAP.md](ROADMAP.md) and [docs/PRODUCT_PLAN.md](docs/PRODUCT_PLAN.md): unlocking the vault with Windows Hello, watching real browser and chat stores, a recovery checklist after a theft, and an installer.
