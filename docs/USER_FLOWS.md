# How people use GotchU

The journeys GotchU is designed around. Steps that are not built yet are marked "planned". The diagrams
render on GitHub.

## 1. Who it is for, and where each person starts

```mermaid
flowchart LR
    home(["Home user or family"]) --> exp
    gamer(["Student or gamer"]) --> chk
    creator(["Creator or streamer"]) --> exp
    crypto(["Crypto holder"]) --> trip
    dev(["Developer"]) --> vlt
    biz(["Small business"]) --> hard
    admin(["IT admin"]) --> json

    chk["Check a download"]
    exp["What a thief could take"]
    trip["Tripwire"]
    vlt["Vault"]
    hard["Lock down this PC"]
    json["Command line with --json"]

    chk --> exp
    exp --> hard
    hard --> trip
    trip --> vlt
```

Everyone ends up on the same path. The entry point is whichever question that person arrives with.

## 2. First ten minutes on a new PC

```mermaid
flowchart TB
    start(["Open GotchU"]) --> scan["Scan this PC"]
    scan --> clean{"Signs of infection?"}
    clean -- "Yes" --> infected["Go to flow 5"]
    clean -- "No" --> exp["What a thief could take"]
    exp --> seen["You see the count:<br/>saved passwords, sessions, keys, wallets"]
    seen --> hard["Lock down this PC"]
    hard --> pick{"For each lock:<br/>what it stops, what it costs"}
    pick -- "Turn on" --> prompt["Windows asks, you say yes<br/>old setting is saved"]
    pick -- "Not now" --> alt["GotchU tells you the alternative"]
    prompt --> trip["gotchu tripwire --on"]
    alt --> trip
    trip --> vault["gotchu vault create<br/>write the recovery key on paper"]
    vault --> done(["Protected, and you know what is left exposed"])
```

## 3. "I just downloaded something"

```mermaid
flowchart TB
    dl(["A zip, installer or script arrives"]) --> chk["Check it<br/>GotchU reads it without running it"]
    chk --> verdict{"Verdict"}
    verdict -- "DANGER" --> del["Do not open it. Delete it.<br/>Findings say which trick was found"]
    verdict -- "CAUTION" --> think["Read the findings.<br/>Open only if you trust the source"]
    verdict -- "NOTHING FOUND" --> open["Open it.<br/>Not a guarantee: the locks and the tripwire still stand guard"]
    open --> ran{"Something odd afterwards?"}
    ran -- "Yes" --> scan["Scan this PC, go to flow 5"]
    ran -- "No" --> fine(["Carry on"])
```

## 4. "The alarm went off"

```mermaid
flowchart TB
    alarm(["Warning window:<br/>a program read a decoy"]) --> me{"Was it you?<br/>For example you opened the decoy folder"}
    me -- "Yes" --> clear["gotchu tripwire --restore<br/>clears the alarm and any block"]
    me -- "No, or not sure" --> offline["Disconnect from the internet"]
    offline --> who["gotchu tripwire<br/>shows which program, and when"]
    who --> scan["gotchu scan"]
    scan --> away["From another device:<br/>change passwords, sign out everywhere"]
    away --> respond["Recovery checklist (planned: respond)"]
    clear --> ok(["Back to normal"])
    respond --> ok
```

With `--cut` switched on, the program that read the decoy has already lost its internet by the time the
window appears.

## 5. "I think I was infected"

```mermaid
flowchart TB
    worry(["Something feels wrong"]) --> scan["Scan this PC"]
    scan --> found{"Findings?"}
    found -- "DANGER" --> act["Each finding says what was seen<br/>and what to do"]
    found -- "Nothing" --> trip["gotchu tripwire<br/>any alarms or unknown readers?"]
    trip --> exp["What a thief could take<br/>this is what to assume is gone"]
    act --> exp
    exp --> change["From another device: change passwords,<br/>sign out everywhere, replace keys"]
    change --> harden["Lock down this PC so it is harder next time"]
    harden --> done(["Recovered"])
```

A clean scan is not proof. The exposure report is the honest list of what an attacker could have taken.

## 6. Moving a key into the vault and using it

```mermaid
flowchart TB
    key(["A key file in Downloads"]) --> stolen{"Could it already have been stolen?"}
    stolen -- "Yes" --> replace["Replace the key first.<br/>Hiding a stolen key does not help"]
    stolen -- "No" --> add
    replace --> add["gotchu vault add --move key.pem"]
    add --> verify["GotchU encrypts it, reads it back,<br/>and only then deletes the original"]
    verify --> need(["Later: you need the key"])
    need --> use["gotchu vault use key.pem -- ssh -i {} host"]
    use --> gone["The key exists on disk only while ssh runs"]
```

## 7. Changing your mind

Every change GotchU makes has a way back.

| You did | To undo |
|---|---|
| Turned on a lock | `gotchu harden --undo <lock>`, or "Put it back" in the window |
| Turned on the tripwire | `gotchu tripwire --off` removes the decoys, the watcher and the Windows setting |
| Got an alarm, dealt with it | `gotchu tripwire --restore` lifts the block and clears the alarm |
| Put a file in the vault | `gotchu vault get <name>` takes it out again |
