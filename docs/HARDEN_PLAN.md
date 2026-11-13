# `gotchu harden` - research and plan

Goal: move from "spot bad things" to "make the attack fail even when it is not recognised".
Detection (`check`, `scan`) stays as the safety net; `harden` is the core.

## Product rules agreed with the owner (2026-11-13)

1. Nothing is permanent: rules and locks are reviewed and updated continuously.
2. Never demand a reinstall if an alternative exists; offer the alternative first.
3. Test on Windows Home, not only Pro; state per lock which editions it works on.
4. Every lock shows, before it is applied: what it protects against, what gets less convenient,
   and the alternative if the user declines. Every change is reversible from the tool.

## Research findings (checked November 2026)

| Topic | Finding | Source |
|---|---|---|
| Smart App Control (SAC) without reinstall | Since the April 2026 update for Windows 11 25H2, SAC can be switched on/off in Windows Security > App & browser control. Before that it needed a clean install. | topedia, ciaops, pureinfotech (links below) |
| SAC known issue | October 2026 update KB5127648 greyed the switch out on some PCs; reported fixed, with a registry workaround in the meantime. Must be detected, not assumed. | bleepingcomputer, it-connect |
| Attack-surface-reduction (ASR) rules on Home | Microsoft: ASR is available on any edition with Defender Antivirus, Windows 11 Home named. Set locally with `Add-MpPreference -AttackSurfaceReductionRules_Ids/-_Actions` (0 off, 1 block, 2 audit, 6 warn). Defender must be the active antivirus. Some rules should run in audit first. | learn.microsoft.com ASR overview / configure |
| Custom App Control (WDAC) policies on Home | Unclear. CiTool ships in Windows 11 22H2+, but Microsoft's policy edition list names Pro/Enterprise/Education, not Home. Treat as unsupported on Home until tested; SAC is the Home route. | learn.microsoft.com App Control |
| Stolen browser sessions | Chrome 146+ on Windows ships Device Bound Session Credentials: session cookies are tied to a key in the PC's security chip, so a stolen cookie is useless elsewhere. Needs a TPM and site support; does not protect saved passwords. Earlier App-Bound Encryption was bypassed by stealers in 2024. | security.googleblog.com, helpnetsecurity |

Sources:
- https://blog-en.topedia.com/2026/04/smart-app-control-in-windows-11-can-now-be-re-enabled-without-reinstalling/
- https://blog.ciaops.com/2026/04/16/existing-systems-can-now-enable-windows-smart-app-control-and-you-should/
- https://pureinfotech.com/enable-smart-app-control-windows-11/
- https://www.bleepingcomputer.com/news/microsoft/microsoft-fixes-smart-app-control-broken-by-october-windows-update/amp/
- https://www.it-connect.tech/windows-11-kb5127648-breaks-smart-app-control-in-october-2026-update/
- https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-overview
- https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-configure
- https://learn.microsoft.com/en-gb/windows/security/application-security/application-control/app-control-for-business/deployment/deploy-appcontrol-policies-with-script
- https://security.googleblog.com/2026/04/protecting-cookies-with-device-bound.html
- https://helpnetsecurity.com/2026/04/10/google-chrome-device-bound-session-credentials

Still to research before building the matching lock: exact ASR rule IDs and which are safe to block
without audit; Controlled Folder Access false positives with games and dev tools; memory integrity
driver incompatibilities; passkey/password-manager migration flows per browser.

## Baseline measured on the test PC (Windows 11 Home Single Language, build 26200)

Smart App Control off - ASR rules 0 enabled - Controlled Folder Access off - network protection off -
cloud block level default - memory integrity off - daily account is an administrator - no backup.
On: unwanted-app blocking, vulnerable-driver blocklist, real-time protection.

## The locks

| # | Lock | How it is set | Inconvenience to tell the user | If declined |
|---|---|---|---|---|
| 1 | Only trusted programs run (Smart App Control) | Windows Security switch; tool detects state and guides, falls back to the workaround or reset advice if greyed out | Unsigned tools, cracks, some indie apps and dev builds will not run; no per-app exception | ASR "block untrusted executables" + `check` before every run |
| 2 | Block common malware techniques (ASR rules) | `Add-MpPreference`, audit first for noisy rules | Some macros, scripts and older installers are blocked | Leave in warn mode |
| 3 | Protect documents from ransomware (Controlled Folder Access) | `Set-MpPreference -EnableControlledFolderAccess` | Games and tools that save into Documents need allowing once | Backups only |
| 4 | Block known-bad sites for every app (network protection) | `Set-MpPreference -EnableNetworkProtection` | Rare false blocks | Browser SmartScreen only |
| 5 | Stricter cloud checking of new files | `Set-MpPreference -CloudBlockLevel High` | Unknown files held a few seconds longer | Default level |
| 6 | Protect the Windows core (memory integrity) | Windows Security switch + reboot | Old drivers may stop loading | Driver blocklist only |
| 7 | Daily use on a standard account | Guided: create admin account, demote daily one | Password prompt when installing software | Keep UAC at highest level |
| 8 | Secrets that cannot be stolen | Guided: password manager, passkeys, 2FA; find keys/recovery codes on disk; Chrome 146+ | One-time migration effort | Sign-out-everywhere runbook after an incident |
| 9 | Backups | File History / OneDrive known-folder backup check | Needs a drive or cloud space | - |

## Build order

1. `harden` audit (read-only): state of every lock, edition support, plain explanation, score. CLI + UI page.
2. Apply with undo for locks 2-5 (PowerShell-settable): show change, save previous value to a local
   journal, apply, re-read to confirm, `harden --undo`.
3. Guided locks (1, 6, 7, 8, 9): detect, explain, deep-link to the right Windows settings page, re-check.
4. Drift watch: re-audit on a schedule, alert when a lock is switched off.
5. Test matrix: Home and Pro, with Defender active and with third-party antivirus.

Verify each step on the test PC: audit matches Windows Security; apply changes exactly the stated
setting; undo restores the previous value; ordinary apps (browser, Steam, VS Code, Docker) still work.
