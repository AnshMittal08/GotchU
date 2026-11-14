# Changelog

What changed in each release, newest first.

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
