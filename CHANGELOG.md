# Changelog

What changed in each release, newest first.

## 0.2.0

GotchU is now an app with its own window. After the first run you do not need a terminal.

- `gotchu app` opens the window. It offers to add GotchU to the Start menu and the desktop.
- The first run shows a welcome that says what GotchU is for and has one button, "Turn on protection".
- Home says in plain words whether you are protected, and lists your protection with a switch for each:
  the theft alarm, cutting the thief off from the internet, the right-click check, and (optional) stricter
  Windows settings. Beside it is the dial: one ring per protection, turning into line like a safe's
  combination when it is on. Its rim is a 24-hour clock that plots alarms and unusual reads at their time.
- Home also lists recent activity and the downloads worth checking.
- An alarm shows on Home and asks whether you know the program. "Yes" lifts the block, "No" opens the checklist.
- Light and dark looks, following Windows, with a button to switch.
- New pages: check a download (with "Move it to the Recycle Bin" and "Show in folder"), the checklist
  after a bad click (ticks are remembered), what a thief could take, scan, and the tripwire log.
- "Check with GotchU" in File Explorer's right-click menu. On Windows 11 it is under "Show more options".
- With the decoys on, GotchU opens at sign-in if an alarm was not answered.
- The stricter Windows settings are optional and do not count against "protected".
- The alarm window now points to the app instead of listing commands to type.
- **Fix: GotchU listed itself as a program to review.** When it counted your saved logins, that read was
  written down like any other program's. Its own reads, at the moments it makes them, are now set aside.
- **Fix: GotchU tripped its own alarm.** Looking at its own decoys (to count what a thief could take, or
  to check whether a wallet app had moved in) counted as a read, so `gotchu exposure`, `respond`,
  `tripwire` and the window raised a false alarm naming python.exe, and with the internet cut on would
  have blocked Python. Decoys are now recognised by size and date, without opening them. If you saw
  alarms naming python.exe, they were this. Answer "Yes, it is mine" in the window to clear them.
- The fonts (Barlow, SIL Open Font License) ship inside the package. The window loads nothing from the internet.
- Run `gotchu setup`, or press "Update GotchU's helpers" in the window, after updating.

## 0.1.2

Found by a test pass over the published package (108 checks on Python 3.10 to 3.14).

- **Security fix.** GotchU started Windows PowerShell by name. Run from inside a folder that held a file
  called `powershell.exe` (an extracted download, for example), Windows would start that file instead.
  GotchU now always starts Windows' own PowerShell by its full path. Update if you use 0.1.0 or 0.1.1.
- `check` no longer skips files in very deep folders (paths longer than 260 characters). Before, they
  were silently left out of the verdict.
- `check` on a file whose name has letters the console cannot show (Hindi, emoji) no longer crashes
  when the output is redirected to a file or another program. Such letters print as `?`.
- One file Windows will not show no longer stops the check of a whole folder. It is listed as unreadable.
- A mistyped command now ends with exit code 3 (could not run). It used to end with 2, which means
  "dangerous" everywhere else.
- Clearer message when a path does not exist or cannot be seen.
- The tripwire alarm window has new wording: what happened, what GotchU did, what to do next, and what
  to do if it is a false alarm. Run `gotchu setup` after updating so the watcher uses it.
- The window (`gotchu ui`) answers a malformed request with a plain error instead of failing.

## 0.1.1

- Shorter README with two diagrams. The full command descriptions moved to `docs/COMMANDS.md`.
- No code changes.

## 0.1.0

- First release on PyPI: `check`, `scan`, `exposure`, `harden`, `respond`, `tripwire`, `vault`, `setup`, `ui`.
