# How GotchU is built

Diagrams of the parts, who talks to whom, and what runs with which rights. They describe the code as it
is today; things that are planned but not built are marked. The diagrams render on GitHub.

## 1. The parts

```mermaid
flowchart TB
    user(["You"])

    subgraph entry["Ways in"]
        cli["Command line<br/>gotchu ..."]
        ui["Local window<br/>gotchu ui"]
    end

    subgraph core["GotchU, running as you (no special rights)"]
        check["check<br/>inspect a download"]
        scan["scan<br/>signs of infection"]
        exposure["exposure<br/>what a thief could take"]
        harden["harden<br/>Windows protections"]
        tripwire["tripwire<br/>decoys and watched stores"]
        vault["vault<br/>encrypted key files"]
        map[("secrets_map.json<br/>where apps keep secrets")]
    end

    subgraph elevated["Runs as administrator, only after a Windows prompt"]
        happly["harden_apply.ps1<br/>one setting, then exits"]
        tapply["tripwire_apply.ps1<br/>set up or remove, then exits"]
        watcher["tripwire_watch.ps1<br/>background watcher"]
    end

    subgraph windows["Windows itself"]
        defender["Defender settings"]
        seclog["Security log<br/>who read which file"]
        tasks["Task Scheduler"]
        firewall["Firewall"]
        crypto["bcrypt.dll<br/>AES-256-GCM"]
    end

    user --> cli
    user --> ui
    ui --> check & scan & exposure & harden
    cli --> check & scan & exposure & harden & tripwire & vault
    exposure --> map
    tripwire --> map
    harden -- "asks Windows to elevate" --> happly --> defender
    tripwire -- "asks Windows to elevate" --> tapply
    tapply --> tasks & seclog
    tasks -- "starts at sign-in" --> watcher
    seclog --> watcher
    watcher --> firewall
    vault --> crypto
```

The window covers check, scan, exposure and harden. The tripwire and the vault are command line only for now.

## 2. What runs with which rights

GotchU keeps the administrator part as small as it can, because that is the part an attacker would
most like to borrow.

```mermaid
flowchart LR
    subgraph you["Your rights"]
        py["Python code<br/>all analysis and decisions"]
        state[("%LOCALAPPDATA%\gotchu<br/>journal, decoy list, vault")]
    end
    subgraph admin["Administrator rights"]
        once["Setup scripts<br/>run once per change, after a prompt"]
        bg["Watcher<br/>one short script, always on"]
        pf[("C:\Program Files\gotchu<br/>watcher, its settings, alarm log")]
    end
    py -- "Windows permission prompt" --> once
    once --> pf
    pf --> bg
    py -. "can read, cannot change" .-> pf
```

- Everything in `C:\Program Files\gotchu` can be changed only by an administrator. So a program running
  as you cannot edit the script that runs elevated, its list of decoys, or its alarm log.
- The watcher is PowerShell run by Windows' own `powershell.exe`. No Python and nothing from a
  user-writable folder runs elevated in the background.
- The alarm log lives in Program Files, not in your profile, so the elevated watcher never writes into a
  folder that an ordinary program could redirect.

## 3. The local window

```mermaid
sequenceDiagram
    participant U as You
    participant G as gotchu ui
    participant B as Your browser
    U->>G: gotchu ui
    G->>G: listen on 127.0.0.1, random port, make a one-time token
    G->>B: open the page, with the token after the hash sign in the address
    B->>G: GET / (the page itself)
    B->>B: read the token from the address, then remove it from the address bar
    B->>G: POST /api/scan with header X-GotchU-Token
    G->>G: check the token and the Host header
    G-->>B: result as JSON
    Note over G,B: Another website cannot do this. It does not know the token,<br/>and a wrong Host header is refused.
```

## 4. Tripwire: what happens when something reads a watched file

```mermaid
sequenceDiagram
    participant P as Some program
    participant F as Watched file
    participant W as Windows Security log
    participant T as Watcher (elevated)
    participant Y as You
    P->>F: opens and reads
    F->>W: event 4663: this program read this file
    W->>T: new event
    alt reader is Windows search or Defender
        T->>T: ignore
    else file is a decoy
        opt cut is switched on
            T->>T: firewall rule blocks that program's internet
        end
        T->>T: write to alerts.jsonl
        T->>Y: warning window, names the program
    else file is a real store
        alt reader is the owner (name and code-signing publisher match)
            T->>T: ignore
        else anyone else
            T->>T: write to sightings.jsonl, no alarm
        end
    end
    Y->>T: gotchu tripwire shows alarms and the list of readers
```

Decoys are fake wallet files planted only where the real wallet app is not installed. Real stores are
the browser, Telegram and Discord login files from the secrets map. Reads of real stores are listed, not
alarmed, until we know how often honest programs do it.

## 5. Harden: changing a Windows protection, with undo

```mermaid
sequenceDiagram
    participant Y as You
    participant H as harden (your rights)
    participant A as harden_apply.ps1 (elevated)
    participant D as Windows Defender settings
    participant J as Journal file
    Y->>H: turn on a lock
    H->>Y: Windows permission prompt
    Y->>A: Yes
    A->>D: read the current value
    A->>J: save it
    A->>D: set the new value
    A-->>H: ok
    H->>D: read again to confirm it took effect
    H-->>Y: Turned on
    Note over Y,J: Undo reads the saved value, puts it back, and deletes the journal entry.
```

## 6. Vault: how the keys fit together

```mermaid
flowchart TB
    pass["Your passphrase"] -- "scrypt" --> k1["Key 1"]
    rec["Recovery key<br/>on paper"] -- "scrypt" --> k2["Key 2"]
    k1 -- "unwraps" --> dk["Data key<br/>random, never stored in the clear"]
    k2 -- "unwraps" --> dk
    dk -- "AES-256-GCM" --> idx["index.bin<br/>file names"]
    dk -- "AES-256-GCM" --> f1["one .bin per file<br/>contents"]
    subgraph disk["%LOCALAPPDATA%\gotchu\vault"]
        hdr["vault.json<br/>two wrapped copies of the data key"]
        idx
        f1
    end
    hdr -. "holds" .-> dk
```

A thief who copies the vault folder gets the wrapped data key and the encrypted files, and can open
neither without the passphrase or the recovery key. Each file is tied to its own name inside the
vault, so swapping two encrypted files is detected, as is changing a single bit.

`vault use` is the way to use a key without leaving it lying around:

```mermaid
sequenceDiagram
    participant Y as You
    participant V as vault
    participant C as Your command, for example ssh
    Y->>V: gotchu vault use server.pem -- ssh -i {} host
    V->>Y: ask for the passphrase
    V->>V: decrypt into a fresh temporary folder
    V->>C: run with {} replaced by the file's path
    C-->>V: finished
    V->>V: overwrite the file with zeros, delete it and the folder
```

## 7. Where things are kept

| Place | What | Who can change it |
|---|---|---|
| `gotchu/secrets_map.json` (in the code) | Where apps keep secrets, their owners and publishers | Contributors |
| `%LOCALAPPDATA%\gotchu\journal` | Previous value of each lock GotchU turned on | You |
| `%LOCALAPPDATA%\gotchu\decoys.json` | Which decoy files GotchU planted, so it removes only those | You |
| `%LOCALAPPDATA%\gotchu\vault` | The encrypted vault | You (useless without the passphrase) |
| `C:\Program Files\gotchu\tripwire_watch.ps1` | The watcher | Administrators only |
| `C:\Program Files\gotchu\tripwire.json` | Decoys, watched stores, cut on or off, the audit setting from before | Administrators only |
| `C:\Program Files\gotchu\alerts.jsonl`, `sightings.jsonl` | Alarms, and other programs seen reading real stores | Administrators only |

Nothing is sent anywhere. GotchU makes no network connections.

## 8. Planned, not built

`respond` (what was readable at the time of a theft, and a recovery checklist), a background watch that
warns when a lock is switched off, a signed installer, and a driver that blocks reads outright where
today's tripwire can only report them. See [PRODUCT_PLAN.md](PRODUCT_PLAN.md).
