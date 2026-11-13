# GotchU roadmap

Free, open-source, local-first protection for ordinary users and small organisations.

## Why this exists

Antivirus competes on one thing: recognising known-bad files. Modern attacks are built to slip past that
(trusted signed programs, encrypted payloads, padding, scripts), and antivirus does nothing for what
happens next: stolen sessions, leaked keys, and a victim who never learns they were robbed.

gotchu does not try to be another antivirus engine. It adds the layers antivirus leaves out, and it
switches on the strong protections Windows already ships but leaves off.

## Principles

1. **Layers, not a wall.** No tool stops every attack. Each attack type should have to beat several
   independent defences. We publish what is and is not covered.
2. **Tricks, not signatures.** Detect how malware is packaged and behaves, so new variants are caught
   without a daily definitions update.
3. **Local and private.** Nothing leaves the machine unless the user turns that on. No account needed.
4. **Read-only by default.** Any change (delete, quarantine, setting) is shown first and needs a yes.
5. **Plain language.** Every finding says what was seen, why it matters and what to do.
6. **Low false alarms.** A tool that cries wolf gets uninstalled. Every rule is tested against a
   corpus of legitimate software before release.
7. **Small and auditable.** Standard library first; every dependency is a supply-chain risk.

## The five layers

| Layer | Question it answers | Command |
|---|---|---|
| 1. Prevent | Is this safe to open? | `check` |
| 2. Harden | Is my PC set up to resist attacks? | `harden` |
| 3. Detect | Am I infected right now? | `scan` |
| 4. Respond | I was hit - what was taken and what do I do? | `respond` |
| 5. Watch | Tell me the moment something goes wrong | `watch` |

## Attack coverage map

| Attack type | Prevent | Harden | Detect | Respond |
|---|---|---|---|---|
| Fake downloads, cracks, repacks | archive tricks, sideload pairs, padding, disguised names | SmartScreen, reputation-based protection | new programs in Temp/AppData | what ran, what it touched |
| Info-stealers (passwords, cookies, wallets) | as above | fewer saved passwords, keys out of Downloads | secret files read by non-browsers, big uploads | per-site sign-out checklist |
| Phishing email, attachments | macro documents, ISO/LNK/HTA, look-alike links | Office macro blocking, attachment rules | - | account recovery steps |
| "Paste this command" scams (ClickFix) | clipboard/command inspection | script-host restrictions | PowerShell/mshta launched from browser | what the command did |
| Ransomware | - | Controlled Folder Access, backups check, shadow copies | mass file rewrites, ransom notes | isolate, identify family, recovery options |
| Remote-access trojans, backdoors | - | attack-surface-reduction rules | injected system processes, odd connections, remote tools | persistence removal list |
| Persistence (survives reboot) | - | - | tasks, Run keys, services, WMI, startup folder, hijacks | removal with undo |
| Crypto-miners | - | vulnerable-driver blocklist | sustained CPU/GPU by unknown programs, known drivers | removal |
| Malicious browser extensions | extension permission review | - | forced/sideloaded extensions, risky permissions | removal |
| Supply chain (npm, pip, VS Code extensions) | install-script and typosquat checks | - | new packages with install hooks | token rotation list |
| Account takeover (session theft, reused passwords) | - | 2FA and password-reuse review | - | sign-out-everywhere guide per service |
| Network (rogue Wi-Fi, DNS/router hijack) | - | DNS, proxy, router-password checks | changed DNS/proxy/root certificates | reset steps |
| USB and removable media | autorun and LNK checks | autorun off | - | - |
| Cloud/developer secrets on disk | - | finds keys, tokens, recovery codes lying around | secret files read by unknown programs | which keys to rotate, in what order |

Out of scope, stated openly: kernel rootkits and firmware implants (need a kernel driver),
targeted attacks by well-funded groups, phone-only attacks, and physical access. For these we
point to the right tool instead of pretending.

## Phases

### Phase 1 - Core (in progress)
- [x] `check`: pre-run inspection of zips, folders and files (padding, hidden payloads, wrapper
      engines, sideload pairs, disguised programs, shortcuts, scripts).
- [ ] `check`: 7z/rar/ISO/MSI, Office macros, PDF actions, installers (NSIS, Inno), nested archives.
- [x] `scan`: live signs of compromise - system-process imposters, hijacked dllhost, programs running
      from Temp or drop folders, sideload pairs beside running programs, download-and-run commands,
      hidden/admin auto-start tasks, start-up entries in Temp, proxy, Defender off, forced extensions.
- [ ] `scan`: services, WMI subscriptions, start-up folder, DNS and root certificates, browser
      extension permissions, large uploads by unknown programs (SRUM, needs admin).
- [x] `ui`: local window (safety-sign design) for `check` and `scan`; token-protected, 127.0.0.1 only.
- [x] `exposure`: what a thief could take right now - counts saved passwords, stored sessions, chat
      sessions, cloud logins, key files and wallets from `secrets_map.json`, and tries to open each
      store the way an ordinary program would. Counts only; never decrypts, copies or prints a secret.
      Direction and later phases (decoys, tripwire, vault): docs/PRODUCT_PLAN.md.
- [x] `tripwire`: decoy wallet files (only for apps that are not installed) with Windows file-read
      auditing; an elevated watcher in Program Files raises a warning window when one is read and,
      with `--cut`, blocks that program from the internet. `--off` removes everything it added.
      Verified live on Windows 11 Home: alarm logged, the reading program lost its internet, others kept it.
- [x] `tripwire`: also watches real stores that have a known owner (browser logins, sessions and
      autofill; Telegram's key file; Discord's storage). A read by any program other than the owner -
      matched by name and by code-signing publisher - is listed for review. No alarm yet, on purpose.
- [x] `tripwire`: decoys are removed by fingerprint, never by deleting their folder, so a wallet app
      installed into a decoy folder later keeps its data; `--on` retires such decoys. A decoy read by a
      signed program installed in Program Files (antivirus, backup) is listed for review, not alarmed or cut.
- [ ] `tripwire`: after a soak period, raise an alarm for real-store reads too; page in the window;
      decoys outside wallets (documents, cloud keys); opt-in online decoys; publishers for Brave,
      Vivaldi, Opera and Signal (not yet checked on a real install, so matched by name only).
- [x] `vault`: key files encrypted with Windows' AES-256-GCM under a passphrase (scrypt), with a paper
      recovery key; file names are encrypted too. `add --move` deletes the original only after the vault
      copy is read back and matches; `use` gives a file to one command and removes it afterwards.
      Checked against the published AES-GCM test answer; wrong passphrase and tampering are rejected.
- [ ] `vault`: unlock with Windows Hello; page in the window; change passphrase; guides for SSH keys
      held by Windows Hello, short-lived cloud sign-in, Telegram passcode, moving browser passwords out.
- [ ] `respond`: timeline of what ran, inventory of what was readable (sites with saved passwords and
      sessions, key files, cloud tokens), prioritised recovery checklist, evidence bundle.
- Verify: rebuilt real-world cases are flagged; a corpus of legitimate software passes clean.

### Phase 2 - Harden and watch (harden is the core of the product; see docs/HARDEN_PLAN.md)
- [x] `harden` audit: 8 locks, each with what it stops, what it costs and the alternative. CLI + UI.
- [x] `harden --on/--undo`: attack-surface-reduction rules (15), Controlled Folder Access, network
      protection, cloud level. Previous setting journalled before the change; verified round trip
      on Windows 11 Home.
- [x] Administrator helpers run only from `C:\Program Files\gotchu`, installed by first use or
      `gotchu setup` with a SHA-256 check; elevation is refused while they differ from GotchU's own copy.
      The harden journal lives there too.
- [ ] Verify live on Windows 11 Home after the move to Program Files: harden on and undo (including an
      older journal), tripwire on, alarm, restore and off, `setup` and `setup --remove`. The PowerShell
      that gotchu builds is tested without the permission prompt; the elevated runs are not yet.
- [ ] `harden`: guided flows with deep links for Smart App Control, memory integrity, standard
      account, backup; SmartScreen, macro blocking, autorun, PowerShell logging; third-party-antivirus case.
- [ ] `harden`: exposure audit - private keys, recovery codes and tokens in Downloads/Desktop, saved
      browser passwords, stale admin tasks, cracked/abandoned software.
- [ ] `watch`: background mode - checks each new download automatically, alerts when a new auto-start
      entry appears or an unknown program reads browser password stores.
- Verify: settings round-trip (enable, confirm, undo); alerts fire on simulated events only.

### Phase 3 - Usable by everyone
- [ ] Desktop app with a plain report, right-click "Check with gotchu", toast alerts.
- [ ] Single signed installer; winget and Microsoft Store listing; automatic signed updates.
- [ ] Languages beyond English (Hindi first).
- [ ] Guided recovery: step-by-step pages for the 50 most-used services.

### Phase 4 - Organisations
- [ ] Rules as data: detection content in versioned, signed rule files, mapped to MITRE ATT&CK,
      with import of community formats (Sigma, YARA).
- [ ] Machine-readable output (JSON, SARIF) and exit codes for scripts and CI.
- [ ] Silent deployment (MSI, Intune, Group Policy) and central policy.
- [ ] Optional self-hosted console: fleet view, alerts, export to SIEM (syslog, webhook).
- [ ] Audit log of every action; role-based access; no data leaves the organisation.

### Phase 5 - Reach
- [ ] macOS and Linux.
- [ ] Developer workflow: pre-install package checks, secret scanning, CI action.
- [ ] Optional reputation lookups (hash only, opt-in).

## Quality bar for every release

- [x] Continuous checks on every push and pull request: lint (ruff), tests on Python 3.10 to 3.13 on
  Windows, PowerShell parse check, package install. Security policy and contributor guide in the repo.
- Tests for each rule, plus a false-alarm run over a corpus of legitimate software.
- Reproducible builds, signed releases, pinned dependencies, published SBOM.
- Threat model and coverage map kept current; known gaps listed.
- Security policy and coordinated disclosure; third-party review before 1.0.
- Licence: Apache-2.0.

## Usage today

    python -m gotchu ui                         # open the window
    python -m gotchu ui <zip, folder or file>   # open the window and check that download
    python -m gotchu check <zip, folder or file> [--json]
    python -m gotchu scan [--json]
    python -m gotchu exposure [--json]          # what a thief could take right now (counts only)
    python -m gotchu tripwire                   # is the tripwire set, and has it been tripped
    python -m gotchu tripwire --on [--cut]      # plant decoys and watch; --cut also blocks the reader's internet
    python -m gotchu tripwire --restore         # after an alarm: lift blocks, clear the alarm
    python -m gotchu tripwire --off             # remove decoys, put Windows back as it was
    python -m gotchu vault create                # make the vault, choose a passphrase, get a recovery key
    python -m gotchu vault add [--move] <file>   # encrypt a file into it (--move deletes the original)
    python -m gotchu vault list | get <name> | remove <name>
    python -m gotchu vault use <name> -- <command with {}>   # file exists only while the command runs
    python -m gotchu harden [--json]            # which protections are on
    python -m gotchu harden --on <lock>         # asr, folder_protection, network_protection, cloud_level
    python -m gotchu harden --undo <lock>       # put it back exactly as it was
    python -m gotchu setup [--remove]           # install, update or remove the administrator helpers

Exit code: 0 nothing found, 1 worth a look, 2 dangerous.
Tests: `python -m unittest`
