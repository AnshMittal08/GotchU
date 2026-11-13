# GotchU product plan - what makes it worth using

Status: agreed with the owner on 2026-11-13. Phases A and B are built, the decoy half of C, and the vault from D.
The product was named GotchU on 2026-11-13 (working name before that: pcguard); the command is `gotchu`.
Progress is tracked in ROADMAP.md; this file holds the reasoning.

## 1. The idea in one line

Antivirus guards the door ("is this file bad?"). gotchu guards the safe ("who is reading your secrets?")
and stays with you after a theft.

Why this is the right fight:

- There are endless kinds of malware, but thieves want a short, known list of things: browser stores,
  messenger sessions, key files, wallets, cloud logins. A short list can be guarded.
- Info-stealers are the main consumer threat: 7.4 million devices infected and 1.7 billion logins taken
  in the first half of 2026 (Flashpoint, via Infosecurity Magazine).
- Antivirus removal does not help afterwards: stolen sessions keep working after the malware is gone.

No plan is bullet-proof. This one is built so that each part is tested against a harmless fake thief
before we claim anything, and each phase has a rule for when to drop it.

## 2. Who it is for, and what each group needs

| Audience | What they lose in a theft | What they need from us |
|---|---|---|
| Home users, families, elders | Email, banking logins, social accounts | One button, plain words, local language, no account |
| Students and gamers (cracks, mods, cheats) | Discord, Steam, game accounts | "Check before you run", and a guard that works even when they run it anyway |
| Creators and streamers | YouTube/Instagram channel through one stolen cookie | Session tripwire, sign-out-everywhere playbook |
| Crypto holders | Wallet files, seed phrases in notes | Vault, decoy wallet, instant alarm |
| Developers and DevOps | SSH keys, cloud keys, `.env`, kubeconfig, tokens | Keys that do not exist as files; vault; rotation order after a theft |
| Freelancers and small businesses | Client data, invoices, shared logins | All of the above with no IT person |
| IT admins and service providers | Many PCs, no visibility | JSON output, silent install, central view (later) |

One engine serves all of them; only the words and the default settings change per audience.

## 3. Moat candidates, rated honestly

A feature is not a moat: anyone can copy a switch. A moat is something that grows with use and is slow
to copy. Rated on that basis.

| # | Candidate | Why it is hard to copy | Strength | When |
|---|---|---|---|---|
| 1 | **Secrets map**: a shared data file of where each app keeps its secrets (browsers, messengers, wallets, cloud tools, games) | Grows with every contributor, like an ad-blocker's filter list. Every other part of gotchu reads it | Strong, compounding | Start in phase A |
| 2 | **Public proof**: a harmless fake thief anyone can run, with a scorecard of what it gets with gotchu on and off | Trust that vendors cannot buy with adverts. Also our own test for every claim | Strong | Phase B |
| 3 | **After-theft playbooks**: per service, how to sign out everywhere, what to change, in what order | Content that compounds; nobody helps victims today | Strong, compounding | Phase E |
| 4 | **Guard the safe**: alarm when a program other than the owner reads a secret store, plus decoys, plus cutting the internet | I found enterprise tools doing this and one open-source Mac tool (Santa). I found no consumer antivirus advertising it, but I only searched, I did not test their products | Medium now, strong with a driver | Phase C |
| 5 | **Free, local, open, no account** | Antivirus companies earn from upsells and data; they cannot copy this without hurting their business | Medium, lasting | Now |
| 6 | **Plain language and local languages** (Hindi first) | Large audience that security tools ignore | Medium | Phase F |
| 7 | **Undo for every change** | Makes people willing to switch protections on | Medium | Done for 4 locks |
| 8 | **Real blocking with a signed driver** | Needs a paid certificate and Microsoft's signing process; hobby projects rarely get there. The big vendors already have drivers | Medium | Phase G |

The hook that gets people in the door is not a moat but matters most for adoption: the **exposure report**
("a thief could take this from your PC right now"). It needs no trust: it only reads and counts.

Not moats: the zip checker, the Windows hardening switches. Useful, easy to copy.

## 4. What we can and cannot protect, per stolen item

| Item | Protection level | How | Checked how |
|---|---|---|---|
| Key files, `.env`, cloud credentials, kubeconfig, recovery codes, private documents | Theft becomes useless | Vault: encrypted with Windows' own crypto, opened by PIN or fingerprint, locks itself | To build and test |
| SSH keys | No file to steal | Key held by Windows Hello. Research: works with `ecdsa-sk` keys, not `ed25519-sk`, and not the "resident" kind | Test on this PC |
| Cloud keys (AWS, Google Cloud) | No long-lived key on disk | Short-lived sign-in instead of key files; gotchu finds leftover key files | Guide; not researched in depth yet |
| Telegram | Theft becomes useless (probably) | Telegram's own local passcode. Most sources say it makes a stolen session unusable; one says the files stay unencrypted. We test it ourselves with the fake thief before claiming it | Must test |
| Saved browser passwords | Mostly | Move to a password manager with a master lock, empty the browser store; gotchu counts what remains | Guide |
| Browser sessions (cookies) | Partly | Cannot be locked away: the browser needs them. Tripwire + cut the internet. Chrome's device-bound sessions help on sites that support them (Chrome 157 is installed here) | Race; measure it |
| Discord | Partly | Same tripwire. The token itself cannot be locked | Race; measure it |
| "You were robbed and do not know it" | Solved | Decoy files that no honest program opens, plus optional online decoys (Canarytokens: a fake cloud key that emails you when a thief uses it; alert takes 2 to 30 minutes) | To build |

Limits we state openly in the product:

1. The tripwire is a race. A big upload loses; a thief that sends cookies first may get some out.
2. An open vault can be read. It beats grab-and-run thieves, not a patient one.
3. Malware that gets administrator rights can switch gotchu off. The standard-account lock is the answer.
4. A vault can lock its owner out. It ships with a paper recovery key.
5. Real blocking, not only alarm, needs the driver in phase G.

## 5. Phases

Each phase has a check that proves it works and a rule for dropping or changing it.

### A. Exposure report (read-only) - done
- Build: secrets map v1 as a data file; `gotchu exposure` counts saved passwords, signed-in sites, key
  files, messenger sessions, wallets, cloud logins. Counts and locations only, never the values.
- Proves it works: counts match what we know was on this PC; a test with a fake profile.
- Drop rule: none; `respond` needs the same inventory.

### B. Fake thief and scorecard - done, folded into A
- As built: not a separate program. `gotchu exposure` opens each store for one byte, as an ordinary
  program would, and reports how many of them a thief could read today.
- Build: a harmless program that tries to open every place in the secrets map and reports "could read"
  or "blocked". It copies nothing, decrypts nothing and never touches the network.
- Proves it works: it reads everything on an unprotected PC.
- Use: every later claim is measured with it.

### C. Decoys and tripwire - decoys done, real stores in observe mode
- As built: `gotchu tripwire` plants four decoy wallet files (only for apps that are not installed). A
  watcher in Program Files, started at sign-in with administrator rights, shows an alarm when one is read
  and, with `--cut`, blocks that program from the internet. Owner's choice: start alert-only, then cut.
- Verified live on Windows 11 Home with a renamed copy of curl: alarm logged, that program lost its
  internet, other programs kept theirs; `--off` removed everything it had added.
- Real stores, built 2026-11-13: every store in the secrets map that has an owner is watched (24 files and
  folders on the test PC). The watcher ignores the owner, recognised by file name and by the publisher
  on its code signature, and writes any other reader to a list shown by `gotchu tripwire`. Verified
  live: a stand-in program reading Chrome's login store was listed; Chrome itself, running, was not.
- Deliberately no alarm for real stores yet. The drop rule below needs a count of honest readers
  (backup tools, antivirus, sync) first; the list is that measurement.
- Known gap: GotchU's own `exposure` report reads these stores, so it appears in the list as python.exe.
- Still to do: turn the list into an alarm after the soak; a page in the window; decoys that are not wallets.
- First, test on this PC whether Windows Home records file reads (`auditpol`, event 4663). Guides say it
  does; a Microsoft forum thread reports cases where the event never appears. One permission prompt, one
  setting, with undo.
- Result, 2026-11-13, Windows 11 Home build 26200: it works. With "File System" auditing on and an audit
  entry on a decoy file, Windows wrote event 4663 naming the reading program (`cmd.exe`) and the file
  31 ms after the read; our check picked it up within 472 ms. The setting was put back afterwards.
  Reading that log needs administrator rights, so the watcher must run elevated.
- Build: decoy files; alarm when a program other than the owner reads a guarded store; option to cut
  that program's internet.
- Proves it works: the fake thief trips the alarm; time from read to alarm is measured.
- Fallbacks if Home does not record reads: Windows' file-activity tracing, then decoys only.
- Drop rule: more than one false alarm a week in normal use on this PC, or alarm slower than 2 seconds.

### D. Vault and "no file to steal" - vault done, guides next
- As built: `gotchu vault` (create, add, list, get, use, remove). One random data key encrypts every file
  and the index of names with Windows' AES-256-GCM; that key is stored wrapped by the passphrase and by a
  recovery key (scrypt). There is no "open" state to forget: every command asks for the passphrase, and
  `use` puts a file on disk only while one command runs. This replaces the auto-lock idea.
- Not built: Windows Hello unlock (passphrase only for now), the guides, a page in the window.
- Build: vault for key files using Windows' built-in encryption (no home-made crypto), recovery key,
  auto-lock; guides for SSH with Windows Hello, short-lived cloud sign-in, Telegram passcode, moving
  browser passwords out.
- Proves it works: fake thief gets nothing usable from the vault; ordinary tools (git, ssh, docker) still work.
- Drop rule: if daily work needs more than one unlock per session, redesign before release.

### E. Respond
- Build: what was readable at the time of a theft, and a recovery checklist in priority order, starting
  with 20 services.
- Proves it works: replay this laptop's incident and compare with what actually had to be done.

### F. Usable by everyone
- Background watch (alerts when a lock is switched off), single signed installer, right-click check,
  Hindi. Note: unsigned Python bundles are often flagged by antivirus, so signing is required, not optional.

### G. Real blocking and organisations
- Signed file-filter driver so reads are blocked, not only reported. Needs an extended-validation
  certificate and Microsoft's attestation signing; price not confirmed, and no open-source discount found.
- JSON output, silent install, central view.

## 6. Risks to the plan

| Risk | Answer |
|---|---|
| False alarms make people uninstall | Drop rules above; every rule tested against ordinary software first |
| A security tool is itself a target | Small code, standard library, signed releases, outside review before 1.0 |
| The secrets map helps thieves | These locations are already in every stealer's source code; the map adds nothing for them |
| One maintainer | The map and playbooks are data files so others can contribute without touching code |
| Over-claiming | Scorecard from the fake thief is published; the limits in section 4 are shown in the product |
| A big vendor copies it | Likely for single features. The map, playbooks and open scorecard are what stay ours |

## 7. Decisions for the owner (answered 2026-11-13)

1. Agree the thesis: "guard the safe" as the centre, with hardening and checking as supporting parts? **Yes.**
2. Build order A to G as above? **Yes.**
3. Allow the phase C test on this laptop (one permission prompt, undoable)? **Yes; it passed.**
4. Online decoys (Canarytokens) send an alert through a third party. Offer as opt-in, or leave out? **Not answered; treated as opt-in.**

## Sources

- https://infosecurity-magazine.com/news/infostealers-17-billion
- https://northpole.security/cookbook/protect-browser-cookies
- https://crowdstrike.com/en-us/blog/how-to-protect-identities-and-sessions-from-infostealers/
- https://www.techradar.com/pro/security/google-chrome-tried-to-block-infostealer-malware-but-these-hackers-say-they-ve-already-beaten-it
- https://www.notebookcheck.net/Account-hijacked-despite-2FA-a-stolen-cookie-is-enough.1364307.0.html
- https://helpdeskgeek.com/track-who-accesses-folder-windows-10-11/
- https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4663
- https://techcommunity.microsoft.com/discussions/windowsinsiderprogram/file-system-auditing---event-id-4663-not-logging/4429279
- https://isc.sans.edu/diary/32888
- https://vpncentral.com/macos-malware-steals-telegram-sessions-without-cracking-2fa/
- https://learn.microsoft.com/en-au/windows-hardware/drivers/install/driver-signing
- https://learn.microsoft.com/da-dk/windows-hardware/drivers/dashboard/code-signing-reqs
- https://docs.canarytokens.org/guide/windows-directory-token
- https://zeltser.com/honeytokens-canarytokens-setup
- https://github.com/PowerShell/Win32-OpenSSH/issues/2413
- https://gist.github.com/daemonhorn/a6af1b76457b2c10b8058d0a2c919bc3
