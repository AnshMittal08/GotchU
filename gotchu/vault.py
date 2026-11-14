"""Vault: key files that are useless to a thief.

A file in the vault is encrypted on disk and can only be opened with your passphrase (or the
recovery key you wrote down). A thief who copies the vault folder gets noise.

How it is built, so it can be checked:
  - Encryption is Windows' own AES-256-GCM (bcrypt.dll). GotchU contains no cipher code.
  - One random data key encrypts everything. That key is stored twice, wrapped by a key
    made from the passphrase and by a key made from the recovery key (scrypt for both).
  - File names are encrypted too: the index is just another encrypted blob.

Limits, stated plainly: while a file is taken out (`get`, or during `use`) it is an ordinary
file again; and malware that records your keyboard can learn the passphrase.
"""
import base64
import ctypes
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import tempfile
from ctypes import wintypes

FOLDER = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "gotchu", "vault")
MAX_FILE = 64 * 1024 * 1024
SCRYPT = {"n": 2 ** 17, "r": 8, "p": 1}          # OWASP's minimum for scrypt; stored in each slot
LEGACY_SCRYPT = {"n": 2 ** 15, "r": 8, "p": 1}   # slots from before the setting was stored with them
TAG_MISMATCH = 0xC000A002


class WrongSecret(Exception):
    """The passphrase or recovery key did not open the vault, or the data was altered."""


class _GcmInfo(ctypes.Structure):   # BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
    _fields_ = [("cbSize", wintypes.ULONG), ("dwInfoVersion", wintypes.ULONG),
                ("pbNonce", ctypes.c_void_p), ("cbNonce", wintypes.ULONG),
                ("pbAuthData", ctypes.c_void_p), ("cbAuthData", wintypes.ULONG),
                ("pbTag", ctypes.c_void_p), ("cbTag", wintypes.ULONG),
                ("pbMacContext", ctypes.c_void_p), ("cbMacContext", wintypes.ULONG),
                ("cbAAD", wintypes.ULONG), ("cbData", ctypes.c_ulonglong), ("dwFlags", wintypes.ULONG)]


def _gcm(key, nonce, data, aad, tag=None):
    """AES-256-GCM through Windows. tag=None encrypts and returns (ciphertext, tag); otherwise decrypts."""
    lib = ctypes.WinDLL("bcrypt")
    args = [ctypes.c_void_p, ctypes.c_void_p, wintypes.ULONG, ctypes.c_void_p, ctypes.c_void_p, wintypes.ULONG,
            ctypes.c_void_p, wintypes.ULONG, ctypes.POINTER(wintypes.ULONG), wintypes.ULONG]
    lib.BCryptEncrypt.argtypes = lib.BCryptDecrypt.argtypes = args
    lib.BCryptOpenAlgorithmProvider.argtypes = [ctypes.POINTER(ctypes.c_void_p), wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.ULONG]
    lib.BCryptSetProperty.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR, ctypes.c_void_p, wintypes.ULONG, wintypes.ULONG]
    lib.BCryptGenerateSymmetricKey.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
                                               wintypes.ULONG, ctypes.c_void_p, wintypes.ULONG, wintypes.ULONG]
    lib.BCryptDestroyKey.argtypes = [ctypes.c_void_p]
    lib.BCryptCloseAlgorithmProvider.argtypes = [ctypes.c_void_p, wintypes.ULONG]

    def ok(status):
        if status & 0xFFFFFFFF == TAG_MISMATCH:
            raise WrongSecret()
        if status:
            raise OSError(f"Windows encryption failed (0x{status & 0xFFFFFFFF:08X})")

    alg, handle = ctypes.c_void_p(), ctypes.c_void_p()
    ok(lib.BCryptOpenAlgorithmProvider(ctypes.byref(alg), "AES", None, 0))
    try:
        mode = ctypes.create_unicode_buffer("ChainingModeGCM")
        ok(lib.BCryptSetProperty(alg, "ChainingMode", mode, ctypes.sizeof(mode), 0))
        ok(lib.BCryptGenerateSymmetricKey(alg, ctypes.byref(handle), None, 0, key, len(key), 0))
        try:
            nonce_buf, aad_buf = ctypes.create_string_buffer(nonce, len(nonce)), ctypes.create_string_buffer(aad, len(aad))
            tag_buf = ctypes.create_string_buffer(tag or b"\0" * 16, 16)
            info = _GcmInfo(cbSize=ctypes.sizeof(_GcmInfo), dwInfoVersion=1,
                            pbNonce=ctypes.addressof(nonce_buf), cbNonce=len(nonce),
                            pbAuthData=ctypes.addressof(aad_buf) if aad else None, cbAuthData=len(aad),
                            pbTag=ctypes.addressof(tag_buf), cbTag=16)
            src = ctypes.create_string_buffer(data, len(data))
            out, done = ctypes.create_string_buffer(len(data)), wintypes.ULONG()
            call = lib.BCryptDecrypt if tag else lib.BCryptEncrypt
            ok(call(handle, src, len(data), ctypes.byref(info), None, 0, out, len(data), ctypes.byref(done), 0))
            return out.raw[:done.value] if tag else (out.raw[:done.value], tag_buf.raw)
        finally:
            lib.BCryptDestroyKey(handle)
    finally:
        lib.BCryptCloseAlgorithmProvider(alg, 0)


def seal(key, data, aad=b""):
    nonce = secrets.token_bytes(12)
    ciphertext, tag = _gcm(key, nonce, data, aad)
    return nonce + ciphertext + tag


def unseal(key, blob, aad=b""):
    return _gcm(key, blob[:12], blob[12:-16], aad, tag=blob[-16:])


def _stretch(secret, salt, cost):
    cost = {k: int(cost[k]) for k in ("n", "r", "p")}
    return hashlib.scrypt(secret.encode("utf-8"), salt=salt, dklen=32, maxmem=2 ** 28, **cost)


def _slot(secret, data_key):
    salt = secrets.token_bytes(16)
    return {"salt": base64.b64encode(salt).decode(), "scrypt": dict(SCRYPT),
            "wrapped": base64.b64encode(seal(_stretch(secret, salt, SCRYPT), data_key, b"gotchu-vault-key")).decode()}


def _save_header(header, folder):
    tmp = os.path.join(folder, "vault.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(header, f, indent=1)
    os.replace(tmp, os.path.join(folder, "vault.json"))


def _tidy_recovery(text):
    return "".join(text.upper().split()).replace("-", "")


def exists(folder=FOLDER):
    return os.path.isfile(os.path.join(folder, "vault.json"))


def create(passphrase, folder=FOLDER):
    """Make an empty vault. Returns the recovery key - shown once, never stored in the clear."""
    if exists(folder):
        raise FileExistsError("There is already a vault here.")
    os.makedirs(folder, exist_ok=True)
    data_key = secrets.token_bytes(32)
    recovery = _new_recovery()
    header = {"version": 1, "passphrase": _slot(passphrase, data_key), "recovery": _slot(recovery, data_key)}
    _save_header(header, folder)
    _save_index(data_key, {}, folder)
    return _grouped(recovery)


def _new_recovery():
    return base64.b32encode(secrets.token_bytes(20)).decode()


def _grouped(recovery):
    return "-".join(recovery[i:i + 4] for i in range(0, len(recovery), 4))


def _load_header(folder):
    with open(os.path.join(folder, "vault.json"), encoding="utf-8") as f:
        return json.load(f)


def change_passphrase(data_key, passphrase, folder=FOLDER):
    """Wrap the data key under a new passphrase. The old one stops working; the files are not touched."""
    header = _load_header(folder)
    header["passphrase"] = _slot(passphrase, data_key)
    _save_header(header, folder)


def replace_recovery(data_key, folder=FOLDER):
    """Make a new recovery key; the old one stops working. Returns the new key - shown once, never stored."""
    recovery = _new_recovery()
    header = _load_header(folder)
    header["recovery"] = _slot(recovery, data_key)
    _save_header(header, folder)
    return _grouped(recovery)


def unlock(secret, folder=FOLDER):
    """Returns the data key for a correct passphrase or recovery key; raises WrongSecret otherwise."""
    header = _load_header(folder)
    for slot, candidate in (("passphrase", secret), ("recovery", _tidy_recovery(secret))):
        entry = header[slot]
        try:
            data_key = unseal(_stretch(candidate, base64.b64decode(entry["salt"]), entry.get("scrypt", LEGACY_SCRYPT)),
                              base64.b64decode(entry["wrapped"]), b"gotchu-vault-key")
        except WrongSecret:
            continue
        if slot == "passphrase" and entry.get("scrypt") != SCRYPT:
            # Wrapped with an older, cheaper setting: wrap it again with today's, now that the passphrase is known.
            header["passphrase"] = _slot(secret, data_key)
            _save_header(header, folder)
        return data_key
    raise WrongSecret()


def _save_index(data_key, index, folder):
    blob = seal(data_key, json.dumps(index).encode(), b"index")
    tmp = os.path.join(folder, "index.tmp")
    with open(tmp, "wb") as f:
        f.write(blob)
    os.replace(tmp, os.path.join(folder, "index.bin"))


def names(data_key, folder=FOLDER):
    with open(os.path.join(folder, "index.bin"), "rb") as f:
        return json.loads(unseal(data_key, f.read(), b"index"))


def add(data_key, path, folder=FOLDER, name=None, move=False):
    """Encrypt a file into the vault. With move=True the original is deleted, but only after the
    vault copy has been read back and matches."""
    name = name or os.path.basename(path)
    index = names(data_key, folder)
    if name in index:
        raise FileExistsError(f"The vault already holds a file called {name}. Use --name to store it under another name.")
    if os.path.getsize(path) > MAX_FILE:
        raise ValueError("That file is too large for the vault (limit 64 MB). The vault is meant for keys and secrets.")
    with open(path, "rb") as f:
        plain = f.read()
    file_id = secrets.token_hex(16)
    with open(os.path.join(folder, file_id + ".bin"), "wb") as f:
        f.write(seal(data_key, plain, file_id.encode()))
    index[name] = file_id
    _save_index(data_key, index, folder)
    if move:
        if get(data_key, name, folder) != plain:
            raise OSError("The vault copy did not match, so the original was left in place.")
        os.remove(path)
    return name


def get(data_key, name, folder=FOLDER):
    index = names(data_key, folder)
    if name not in index:
        raise KeyError(f"The vault has no file called {name}.")
    with open(os.path.join(folder, index[name] + ".bin"), "rb") as f:
        return unseal(data_key, f.read(), index[name].encode())


def remove(data_key, name, folder=FOLDER):
    index = names(data_key, folder)
    if name not in index:
        raise KeyError(f"The vault has no file called {name}.")
    os.remove(os.path.join(folder, index.pop(name) + ".bin"))
    _save_index(data_key, index, folder)


def _vault_files(folder):
    return [n for n in os.listdir(folder) if n == "vault.json" or n.endswith(".bin")]


def backup(dest, folder=FOLDER):
    """Copy the vault, still encrypted, into a new or empty folder. Returns how many files were copied."""
    if os.path.isdir(dest) and os.listdir(dest):
        raise FileExistsError(f"{dest} is not empty. Choose a new folder, so nothing in it is overwritten.")
    os.makedirs(dest, exist_ok=True)
    files = _vault_files(folder)
    for name in files:
        shutil.copy2(os.path.join(folder, name), os.path.join(dest, name))
    return len(files)


def restore(src, folder=FOLDER):
    """Bring a backup back. Only onto a PC with no vault, so a vault in use is never overwritten."""
    if exists(folder):
        raise FileExistsError("There is already a vault on this PC, and restoring would replace it. Nothing was changed.")
    if not all(os.path.isfile(os.path.join(src, name)) for name in ("vault.json", "index.bin")):
        raise ValueError(f"{src} does not hold a gotchu vault backup.")
    os.makedirs(folder, exist_ok=True)
    for name in _vault_files(src):
        shutil.copy2(os.path.join(src, name), os.path.join(folder, name))


def use(data_key, name, command, folder=FOLDER):
    """Run a command with the file present only while it runs. '{}' in the command is the file's path."""
    plain = get(data_key, name, folder)
    holder = tempfile.mkdtemp(prefix="gotchu-")
    path = os.path.join(holder, name)
    try:
        with open(path, "wb") as f:
            f.write(plain)
        return subprocess.run([part.replace("{}", path) for part in command]).returncode
    finally:
        try:
            with open(path, "wb") as f:
                f.write(b"\0" * len(plain))
            os.remove(path)
            os.rmdir(holder)
        except OSError:
            pass
