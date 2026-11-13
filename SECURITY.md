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
- The only code that runs elevated in the background is one short script, run from Program Files.
- The local window listens on 127.0.0.1 only, needs a one-time token, and checks the Host header.
- Encryption is Windows' own AES-256-GCM; GotchU contains no cipher code.

## Supported versions

Only the latest version on the `main` branch.
