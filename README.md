# GotchU

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
| `gotchu ui` | All of the above in a local window, except the tripwire. |

## Run it

Needs Windows 10 or 11 and Python 3.10 or newer. No other packages.

    python -m gotchu ui
    python -m gotchu exposure
    python -m gotchu tripwire --on

Tests: `python -m unittest`

## Promises

- **Local.** Nothing leaves your PC. No account.
- **Read-only unless you say so.** A change needs your yes and a Windows permission prompt, and can be undone.
- **Plain language.** Every finding says what was seen, why it matters and what to do.
- **Honest limits.** No tool stops every attack. The tripwire catches a thief that sweeps for wallets, not
  every thief; a patient attacker with administrator rights can switch any tool off.

## Where it is going

See [ROADMAP.md](ROADMAP.md) and [docs/PRODUCT_PLAN.md](docs/PRODUCT_PLAN.md): a vault that makes stolen key
files useless, watching real browser and chat stores, a recovery checklist after a theft, and an installer.
