# GotchU commands in detail

The short version is in the [README](../README.md). This page says exactly what each command does.


| Command | Question it answers |
|---|---|
| `gotchu check <file>` | Is this download safe to open? Reads it without running it and looks for the packaging tricks malware uses, including password-protected archives and disk images. It opens zip files and folders; a 7z, RAR or other archive is reported as not looked inside, never as clean. |
| `gotchu scan` | Am I infected right now? Looks at running programs and what starts with Windows (tasks, services, the Start-up folder), the hosts file, and browser extensions loaded from a folder instead of the store. |
| `gotchu exposure` | What could a thief take from this PC today? Counts saved passwords, sessions, keys and wallets. Never shows or copies one. |
| `gotchu harden` | Which Windows protections are off? Turns four of them on, saving the old setting so `--undo` is exact. |
| `gotchu respond` | I ran something bad. What do I do? A checklist built from what is on this PC, in the order to do it. `--sites` adds the websites that have a password saved here (names only). |
| `gotchu tripwire` | Plants decoy files (fake wallets and fake browser logins) no honest program opens. When one is read you get an alarm, and with `--cut` that program loses its internet. It also lists any program, other than the owner, that reads your browser, Telegram or Discord logins. Signed programs installed in Program Files, such as antivirus and backup tools, are listed rather than alarmed; an unsigned program reading your logins is put at the top of the report. It also tells you if its watcher has stopped. |
| `gotchu vault` | Keeps key files encrypted with a passphrase, so a stolen copy is useless. `vault use` hands a key to one command and removes it afterwards. `vault passphrase` and `vault recovery` replace a forgotten passphrase or a lost recovery key. `vault backup` copies the vault, still encrypted, to another drive; `vault restore` brings it back. |
| `gotchu setup` | Installs or updates the small scripts that run with administrator rights, in `C:\Program Files\gotchu`. Done for you the first time harden or the tripwire needs them; run it yourself after updating GotchU. `--remove` takes them away again. |
| `gotchu ui` | A local window for check, scan, exposure and harden, and the tripwire's alarms and programs to review. |

## Examples

    python -m gotchu ui
    python -m gotchu exposure
    python -m gotchu tripwire --on
    python -m gotchu vault create
    python -m gotchu vault add --move my-server-key.pem
    python -m gotchu vault use my-server-key.pem -- ssh -i {} user@host

If the `gotchu` command is on your PC (after `pip install gotchu`), you can type `gotchu` instead of
`python -m gotchu`. Both do the same thing.
