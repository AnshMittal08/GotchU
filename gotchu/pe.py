"""Minimal read-only parser for Windows programs (PE files: .exe / .dll).

Only answers two questions, without running anything:
  - does the file carry an embedded digital signature?
  - which DLL names does it ask Windows to load?
"""
import struct


class PEInfo:
    def __init__(self, signed, imports, original_name):
        self.signed = signed
        self.imports = imports  # lower-case DLL names
        self.original_name = original_name  # name the maker gave the file, or None


_ORIGINAL = "OriginalFilename".encode("utf-16-le")


def _original_name(data):
    """Read the maker's file name from the version resource (survives renaming)."""
    i = data.find(_ORIGINAL)
    if i < 0:
        return None
    i += len(_ORIGINAL)
    while data[i:i + 2] == b"\0\0":
        i += 2
    end = data.find(b"\0\0\0", i, i + 520)
    if end < 0:
        return None
    return data[i:end + 1].decode("utf-16-le", "ignore").strip("\0") or None


def parse(data):
    """Return PEInfo, or None if `data` is not a PE file."""
    try:
        if data[:2] != b"MZ":
            return None
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe:pe + 4] != b"PE\0\0":
            return None
        n_sections, = struct.unpack_from("<H", data, pe + 6)
        opt_size, = struct.unpack_from("<H", data, pe + 20)
        opt = pe + 24
        magic, = struct.unpack_from("<H", data, opt)
        dirs = opt + (112 if magic == 0x20B else 96)  # PE32+ vs PE32

        def directory(i):
            return struct.unpack_from("<II", data, dirs + 8 * i)

        sections = []
        for i in range(n_sections):
            o = opt + opt_size + 40 * i
            vsize, vaddr, rsize, raddr = struct.unpack_from("<IIII", data, o + 8)
            sections.append((vaddr, max(vsize, rsize), raddr))

        def offset(rva):
            for vaddr, size, raddr in sections:
                if vaddr <= rva < vaddr + size:
                    return rva - vaddr + raddr
            return None

        signed = directory(4)[1] > 0  # security directory holds the signature

        imports = set()
        o = offset(directory(1)[0]) if directory(1)[0] else None
        while o is not None and o + 20 <= len(data):
            name_rva, = struct.unpack_from("<I", data, o + 12)
            if name_rva == 0:
                break
            n = offset(name_rva)
            if n is not None:
                end = data.find(b"\0", n, n + 260)
                if end > n:
                    imports.add(data[n:end].decode("latin-1").lower())
            o += 20
        return PEInfo(signed, imports, _original_name(data))
    except (struct.error, IndexError):
        return None
