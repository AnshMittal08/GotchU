# Security policy

GotchU is a security tool, so a weakness in it matters more than in most software.

## Reporting a problem

Please do not open a public issue for a security weakness. Use GitHub's private reporting instead:
on the repository page, choose **Security**, then **Report a vulnerability**.

Include what you did, what happened and which version (`gotchu --version`). You will get a reply
as soon as the maintainer has read it; this is a one-person project, so allow a few days.

## What counts

- Anything that lets a program without administrator rights make GotchU's elevated parts
  (the tripwire watcher and the settings scripts) do something for it.
- Anything that makes the vault give up a file without the passphrase or recovery key.
- A way for GotchU to print, copy or send a secret it is only supposed to count.
- A way for a web page to talk to the local window.

A detection rule that misses some malware is a normal bug, not a vulnerability: open an ordinary issue.

## How GotchU limits its own risk

- Standard library only; no third-party packages to be poisoned.
- The only code that runs elevated in the background is one short script, run as SYSTEM from Program Files.
- Code that runs elevated always runs from `C:\Program Files\gotchu`, never from GotchU's own folder.
  It is copied there only on first use or by `gotchu setup`, each copy checked against the SHA-256 of the
  file GotchU read, and GotchU will not ask for elevation while its own copy differs from the installed one.
- Elevated helpers check anything they read from your profile (a SHA-256 for the tripwire's plan, allowed
  values for an old journal) and write only into Program Files.
- The local window listens on 127.0.0.1 only, needs a one-time token, and checks the Host header.
- Encryption is Windows' own AES-256-GCM; GotchU contains no cipher code. Passphrases are stretched with
  scrypt (N=2^17, r=8, p=1).

## Known limit

If GotchU is installed in a folder your account can change (a cloned copy, or Python installed only for
you), a program running as you can change GotchU's Python code, and with it what GotchU asks Windows to
run when you approve a prompt. `gotchu setup` warns when this is the case. Installing GotchU with a Python
that is installed for all users, in Program Files, closes the gap; the planned signed installer will too.

## Supported versions

Only the latest version on the `main` branch.
