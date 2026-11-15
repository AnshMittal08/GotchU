# GotchU commands in detail

The short version is in the [README](../README.md). This page says exactly what each command does.


| Command | Question it answers |
|---|---|
| `gotchu check <file>` | Is this download safe to open? Reads it without running it and looks for the packaging tricks malware uses, including password-protected archives and disk images. It opens zip files and folders, including the zip files inside a folder; a 7z, RAR or other archive (or a zip inside a zip) is reported as not looked inside, never as clean. |
| `gotchu scan` | Am I infected right now? Looks at running programs and what starts with Windows (tasks, services, the Start-up folder), the hosts file, and browser extensions loaded from a folder instead of the store. |
| `gotchu exposure` | What could a thief take from this PC today? Counts saved passwords, sessions, keys and wallets. Never shows or copies one. |
| `gotchu harden` | Which Windows protections are off? Turns four of them on, saving the old setting so `--undo` is exact. |
| `gotchu respond` | I ran something bad. What do I do? A checklist built from what is on this PC, in the order to do it. `--sites` adds the websites that have a password saved here (names only). |
| `gotchu tripwire` | Plants decoy files (fake wallets and fake browser logins) no honest program opens. When one is read you get an alarm, and with `--cut` that program loses its internet. It also lists any program, other than the owner, that reads your browser, Telegram or Discord logins. Signed programs installed in Program Files, such as antivirus and backup tools, are listed rather than alarmed; an unsigned program reading your logins is put at the top of the report. It also tells you if its watcher has stopped. |
| `gotchu vault` | Keeps key files encrypted with a passphrase, so a stolen copy is useless. `vault use` hands a key to one command and removes it afterwards. `vault passphrase` and `vault recovery` replace a forgotten passphrase or a lost recovery key. `vault get --to` takes a folder or a full file name. `vault backup` copies the vault, still encrypted, to another drive; `vault restore` brings it back. |
| `gotchu setup` | Installs or updates the small scripts that run with administrator rights, in `C:\Program Files\gotchu`. Done for you the first time harden or the tripwire needs them; run it yourself after updating GotchU. `--remove` takes them away again. |
| `gotchu uninstall` | Puts back everything GotchU set up, in order: turns off the tripwire (decoys, watcher, internet blocks, the file-audit setting), puts back every Windows setting GotchU changed, removes the helpers from Program Files, the right-click entry, the shortcuts and the check at sign-in, and deletes GotchU's settings and history. It lists the steps and asks first (`--yes` skips the question). It can be run again if a step was declined. The vault is never deleted. Afterwards, `pip uninstall gotchu` removes the program. The window has the same thing at the bottom of Protection. |
| `gotchu app` | Opens GotchU in its own window (Edge or Chrome, shown without tabs or an address bar). Home says whether you are protected and lists your protection with a switch for each: the theft alarm (the decoys), cutting the thief off from the internet, the right-click check, and the optional stricter Windows settings. A dial shows the same state: a padlock in a ring of three arcs, one per protection. An arc fills in green when its protection is on and breathes amber while it is off; the padlock clicks shut when all three are on, and is red during an alarm. Beside it are recent activity and the downloads worth checking. The first run shows a welcome with one button that turns the first three on. From the window you can also check a download and move it to the Recycle Bin, use the vault (everything except `vault use`; it locks itself after 5 quiet minutes and when the window closes), work through the checklist after a bad click, see what a thief could take, scan the PC, read the tripwire log, add or remove the Start-menu and desktop shortcuts, and switch between a light and a dark look. It closes its local server when the window closes. `gotchu app <file>` opens it on a check of that file; this is what "Check with GotchU" in the right-click menu runs. |
| `gotchu ui` | The same window as a tab in your default browser. `--no-browser` only prints its address. |

## Examples

    python -m gotchu app
    python -m gotchu exposure
    python -m gotchu tripwire --on
    python -m gotchu vault create
    python -m gotchu vault add --move my-server-key.pem
    python -m gotchu vault use my-server-key.pem -- ssh -i {} user@host

If the `gotchu` command is on your PC (after `pip install gotchu`), you can type `gotchu` instead of
`python -m gotchu`. Both do the same thing.
