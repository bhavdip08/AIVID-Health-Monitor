"""Small deterministic PEP 517 builder for the two pure Python distributions.

No build-time dependency download is needed. Wheel RECORD uses URL-safe SHA256
hashes for every member and includes packaged dashboard assets.
"""
from __future__ import annotations
import base64
import csv
import hashlib
import io
import os
from pathlib import Path
import tomllib
import zipfile


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    root = Path.cwd()
    project = tomllib.loads((root / "pyproject.toml").read_text())["project"]
    name = project["name"].replace("-", "_")
    version = project["version"]
    info = f"{name}-{version}.dist-info"
    filename = f"{name}-{version}-py3-none-any.whl"
    members = {p.relative_to(root / "src").as_posix(): p.read_bytes() for p in sorted((root / "src").rglob("*"))
               if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc"}
    metadata = ["Metadata-Version: 2.1", f"Name: {project['name']}", f"Version: {version}",
                f"Summary: {project['description']}", f"Requires-Python: {project['requires-python']}", "License: Proprietary"]
    metadata += ["Requires-Dist: " + d for d in project.get("dependencies", [])]
    members[info + "/METADATA"] = ("\n".join(metadata) + "\n\n").encode()
    members[info + "/WHEEL"] = b"Wheel-Version: 1.0\nGenerator: aivid-offline-builder\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    entries = "[console_scripts]\n" + "\n".join(f"{key} = {value}" for key, value in project.get("scripts", {}).items()) + "\n"
    members[info + "/entry_points.txt"] = entries.encode()
    rows = []
    for key, value in members.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(value).digest()).rstrip(b"=").decode()
        rows.append([key, "sha256=" + digest, str(len(value))])
    rows.append([info + "/RECORD", "", ""])
    text = io.StringIO(newline="")
    csv.writer(text, lineterminator="\n").writerows(rows)
    members[info + "/RECORD"] = text.getvalue().encode()
    out = Path(wheel_directory).resolve()
    out.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out / filename, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for key, data in sorted(members.items()):
            z = zipfile.ZipInfo(key, date_time=(2026, 1, 1, 0, 0, 0))
            z.external_attr = 0o644 << 16
            z.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(z, data)
    return filename


def get_requires_for_build_wheel(config_settings=None):
    return []
