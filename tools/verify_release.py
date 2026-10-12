#!/usr/bin/env python3
"""Verify manifest coverage, checksums, modes and absence of secret files."""
import hashlib
import json
from pathlib import Path
import sys


def verify(root):
    manifest = json.loads((root / "RELEASE_MANIFEST.json").read_text())
    ignored = {"RELEASE_MANIFEST.json", "RELEASE_MANIFEST.sig", "SHA256SUMS", "SHA256SUMS.sig"}
    expected = {f["path"] for f in manifest["files"]}
    actual = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}
    if actual - ignored != expected:
        raise ValueError("Release contains missing or unexpected files")
    if any(p.is_symlink() for p in root.rglob("*")):
        raise ValueError("Release contains symbolic links")
    for entry in manifest["files"]:
        p = root / entry["path"]
        if not p.resolve().is_relative_to(root.resolve()):
            raise ValueError("Unsafe manifest path")
        raw = p.read_bytes()
        if hashlib.sha256(raw).hexdigest() != entry["sha256"] or len(raw) != entry["size"]:
            raise ValueError("Release checksum mismatch: " + entry["path"])
        if (p.stat().st_mode & 0o777) != int(entry["mode"], 8):
            raise ValueError("Release mode mismatch: " + entry["path"])
        if p.suffix in (".pem", ".key") and b"PRIVATE KEY" in raw:
            raise ValueError("Release contains a private key")
    print("Release verified: manifest coverage, checksums and permissions")
    return manifest


if __name__ == "__main__":
    verify(Path(sys.argv[1]).resolve())
