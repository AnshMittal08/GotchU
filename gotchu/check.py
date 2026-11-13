"""Pre-run check: inspect a download (zip, folder or single file) WITHOUT running it.

Looks for packaging tricks used by malware that hides from antivirus, rather than
for known-bad files. Every finding says what was seen and why it matters.
"""
import hashlib
import math
import os
import re
import zipfile
from collections import Counter, defaultdict

from . import pe, report
from .report import HIGH, INFO, MEDIUM

SAMPLE = 256 * 1024           # bytes read per file for entropy
MAX_PE = 64 * 1024 * 1024     # largest program we fully parse
SCRIPT_EXT = {".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".scr", ".lnk", ".pif"}
PROGRAM_EXT = {".exe", ".dll", ".scr", ".msi", ".com"}
DOC_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".txt", ".mp4", ".mp3"}
# Formats that are legitimately high-entropy (already compressed).
PACKED_EXT = {".zip", ".7z", ".rar", ".gz", ".xz", ".bz2", ".zst", ".cab", ".png", ".jpg", ".jpeg", ".webp",
              ".gif", ".ogg", ".opus", ".mp3", ".mp4", ".mkv", ".webm", ".avi", ".pak", ".rpa", ".rpyc", ".rpyb",
              ".pyc", ".pyd", ".exe", ".dll", ".msi", ".woff", ".woff2", ".ttf", ".otf", ".jar", ".apk", ".pdf",
              ".bik", ".bk2", ".wem", ".bnk", ".dds", ".ktx", ".astc", ".unity3d", ".assets", ".bundle", ".vpk"}
PACKED_MAGIC = (b"PK\x03\x04", b"7z\xbc\xaf", b"Rar!", b"\x1f\x8b", b"\x89PNG", b"\xff\xd8\xff", b"OggS",
                b"ID3", b"RIFF", b"\x1a\x45\xdf\xa3", b"MZ", b"%PDF", b"RPA-", b"RENPY", b"\xfd7zXZ", b"BZh",
                b"\x78\x01", b"\x78\x9c", b"\x78\xda", b"\x28\xb5\x2f\xfd")
BAIT = re.compile(r"(?i)crack|keygen|activator|patch(ed)?|repack|loader|free[_ -]?download|_free_|_get_|"
                  r"full[_ -]?version|unlocked|premium[_ -]?free|nulled")


class Member:
    """One file inside the thing being checked."""

    def __init__(self, name, size, packed_size, reader):
        self.name = name.replace("\\", "/")
        self.size = size
        self.packed_size = packed_size  # None when not inside an archive
        self._reader = reader

    def read(self, n=-1):
        return self._reader(n)

    @property
    def ext(self):
        return os.path.splitext(self.name)[1].lower()

    @property
    def folder(self):
        return os.path.dirname(self.name)

    @property
    def base(self):
        return os.path.basename(self.name)


def _zip_members(path):
    z = zipfile.ZipFile(path)
    for zi in z.infolist():
        if zi.is_dir():
            continue

        def reader(n, zi=zi):
            with z.open(zi) as f:
                return f.read(n)

        yield Member(zi.filename, zi.file_size, zi.compress_size, reader)


def _dir_members(path):
    for root, _, files in os.walk(path):
        for fn in files:
            full = os.path.join(root, fn)

            def reader(n, full=full):
                with open(full, "rb") as f:
                    return f.read(n)

            yield Member(os.path.relpath(full, path), os.path.getsize(full), None, reader)


def members(path):
    if os.path.isdir(path):
        return list(_dir_members(path))
    if zipfile.is_zipfile(path):
        return list(_zip_members(path))
    size = os.path.getsize(path)

    def reader(n):
        with open(path, "rb") as f:
            return f.read(n)

    return [Member(os.path.basename(path), size, None, reader)]


def entropy(data):
    """0 = all the same byte, 8 = looks completely random (encrypted or compressed)."""
    if not data:
        return 0.0
    total = len(data)
    return -sum(c / total * math.log2(c / total) for c in Counter(data).values())


def download_origin(path):
    """Windows records where a downloaded file came from in a hidden tag."""
    try:
        with open(path + ":Zone.Identifier", "r", errors="replace") as f:
            for line in f:
                if line.startswith("HostUrl="):
                    return line.strip()[8:]
    except OSError:
        pass
    return None


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def analyse(path):
    """Return a list of (severity, title, detail) findings for `path`."""
    findings = []
    items = members(path)

    def add(sev, title, detail):
        findings.append((sev, title, detail))

    bait = bool(BAIT.search(os.path.basename(path)))
    if bait:
        add(MEDIUM, "Name looks like pirated or 'free' software",
            "Cracks, repacks and 'free download' archives are the most common way malware is delivered.")

    padding, blobs, engine = [], [], False
    by_folder = defaultdict(list)
    for m in items:
        by_folder[m.folder].append(m)

        # 1. Padding: a huge file of nothing, added so scanners skip the archive.
        if m.size > 20 * 1024 * 1024:
            if m.packed_size and m.size / max(m.packed_size, 1) > 200:
                padding.append(m)
            elif m.packed_size is None and entropy(m.read(SAMPLE)) < 0.5:
                padding.append(m)

        # 2. Hidden payload: random-looking data in a file that has no reason to be random.
        if m.size > 100 * 1024 and m.ext not in PACKED_EXT and m not in padding:
            head = m.read(SAMPLE)
            if not head.startswith(PACKED_MAGIC) and entropy(head) > 7.9:
                blobs.append(m)

        # 3. Disguises.
        stem_ext = os.path.splitext(os.path.splitext(m.base)[0])[1].lower()
        if m.ext in PROGRAM_EXT | SCRIPT_EXT and stem_ext in DOC_EXT:
            add(HIGH, f"Program disguised as a document: {m.name}",
                "The name ends in a document type followed by a program type; Windows hides the last part.")
        if m.ext == ".lnk":
            add(HIGH, f"Shortcut file inside the download: {m.name}",
                "Shortcuts can silently run commands; real software rarely ships them inside an archive.")
        elif m.ext in SCRIPT_EXT and "/" not in m.name:
            add(MEDIUM, f"Script at the top of the download: {m.name}",
                "Scripts run commands on your PC. Read it, or ask someone who can, before running.")

        if m.name.startswith("renpy/") or m.ext == ".rpa":
            engine = True

    for m in padding:
        add(HIGH, f"Padding file: {m.name} ({m.size // 2**20} MB of empty data)",
            "Makes the download huge so antivirus skips it. Real software has no use for this.")
    # Scrambled data alone is normal (many apps ship compressed assets); it only counts with another trick.
    if blobs and (engine or padding or bait):
        for m in blobs:
            add(HIGH, f"Encrypted, unreadable file: {m.name}",
                "Scrambled data in an unusual file type, next to other tricks - a common way to hide the real malware.")
    elif blobs:
        add(INFO, f"{len(blobs)} unreadable data files (normal for many apps)",
            ", ".join(m.name for m in blobs[:4]) + (" ..." if len(blobs) > 4 else ""))
    if engine and (padding or blobs):
        add(HIGH, "Game engine used as a wrapper",
            "A visual-novel engine (Ren'Py) is bundled with hidden data: a known trick where the 'game' "
            "script unpacks and starts malware.")

    # 4. DLL sideloading: a trusted, signed program that will load an untrusted DLL beside it.
    for group in by_folder.values():
        parsed = {}
        for m in group:
            if m.ext in {".exe", ".dll"} and m.size <= MAX_PE:
                info = pe.parse(m.read())
                if info:
                    parsed[m.base.lower()] = (m, info)
        for exe_name, (exe, info) in parsed.items():
            if not exe_name.endswith(".exe") or not info.signed:
                continue
            planted = [parsed[n][0] for n in sorted(info.imports & set(parsed)) if not parsed[n][1].signed]
            # Unsigned DLLs beside a signed program are common in honest open-source software,
            # so also require that the program was renamed from the name its maker gave it.
            # (Tool suites ship copies like git-upload-pack.exe of git.exe; those keep the original name inside.)
            original = os.path.splitext(info.original_name or "")[0].lower()
            stem = os.path.splitext(exe_name)[0]
            renamed = bool(original) and original not in stem and stem not in original
            if planted and renamed:
                add(HIGH, f"Trusted program paired with an untrusted DLL: {exe.name} + "
                          + ", ".join(d.base for d in planted),
                    "The program is digitally signed but will load an unsigned DLL sitting next to it, and it was "
                    f"renamed (its maker called it {info.original_name}). Malware uses this to run under a trusted "
                    "program's name (DLL sideloading).")

    programs = [m for m in items if m.ext in PROGRAM_EXT]
    add(INFO, f"{len(items)} files, {len(programs)} programs",
        ", ".join(m.name for m in programs[:8]) + (" ..." if len(programs) > 8 else ""))
    return findings


LABELS = {
    "danger": ("DANGEROUS", "Do not run this. It uses tricks that only malware needs."),
    "warn": ("SUSPICIOUS", "Be careful. Don't run it unless you fully trust where it came from."),
    "ok": ("NO KNOWN TRICKS FOUND",
           "This is not a guarantee that it is safe - only that these checks found nothing."),
}


def verdict(findings):
    return LABELS[report.level(findings)]


def result(path):
    extra = {}
    if os.path.isfile(path):
        extra = {"sha256": sha256(path), "origin": download_origin(path)}
    return report.build(path, analyse(path), LABELS, **extra)
