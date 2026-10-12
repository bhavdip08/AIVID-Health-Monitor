#!/usr/bin/env python3
"""Build the entire offline release with one authoritative product version.

The build reads VERSION, validates both pyproject files and package constants,
rebuilds wheels, resolves only from the supplied wheelhouse, generates bootstrap
scripts, SBOM and checksums, signs manifests and packages the final tree.
"""
from __future__ import annotations
import argparse
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile
from datetime import datetime, timezone
from email.parser import BytesParser
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[1])
    p.add_argument("--runtime-dir", type=Path, required=True)
    p.add_argument("--wheelhouse", type=Path, required=True)
    p.add_argument("--signing-key", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--build-id", required=True)
    a = p.parse_args(argv)
    source = a.source.resolve()
    version = (source / "VERSION").read_text().strip()
    if not re.fullmatch(r"[A-Za-z0-9._-]+", a.build_id):
        p.error("Invalid build ID")
    key = serialization.load_pem_private_key(a.signing_key.read_bytes(), password=None)
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 3072:
        p.error("Use an RSA release signing key of at least 3072 bits")
    with tempfile.TemporaryDirectory(prefix="aivid-build-") as temp:
        stage = Path(temp) / ("aivid-health-enterprise-" + version)
        shutil.copytree(source, stage, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".git", ".venv", "dist", "*.log", "node.json", "credentials.txt", "*.key", "*.pem", "SHA256SUMS*", "RELEASE_MANIFEST*", "packaging-runtime-cache"))
        packaging = stage / "packaging"
        runtime = packaging / "runtime"
        runtime.mkdir(parents=True, exist_ok=True)
        runtime_manifest = json.loads((a.runtime_dir / "runtime-manifest.json").read_text())
        rt = runtime_manifest["runtimes"]["linux-x86_64"]
        if sha(a.runtime_dir / rt["filename"]) != rt["sha256"]:
            raise RuntimeError("Input runtime digest does not match supplied manifest")
        shutil.copyfile(a.runtime_dir / rt["filename"], runtime / rt["filename"])
        (runtime / "runtime-manifest.json").write_text(json.dumps(runtime_manifest, indent=2) + "\n")
        wheels = packaging / "wheelhouse"
        wheels.mkdir(exist_ok=True)
        for wheel in a.wheelhouse.glob("*.whl"):
            if not wheel.name.startswith("aivid_"):
                shutil.copyfile(wheel, wheels / wheel.name)
        for project, module in (("backend", "aivid_health"), ("installer", "aivid_installer")):
            metadata = tomllib.loads((stage / project / "pyproject.toml").read_text())["project"]
            if metadata["version"] != version:
                raise ValueError(f"{project} version differs from VERSION")
            init = (stage / project / "src" / module / "__init__.py").read_text()
            if f'__version__ = "{version}"' not in init:
                raise ValueError("Package constant differs from VERSION")
            shutil.copyfile(stage / "tools/wheelbuild.py", stage / project / "wheelbuild.py")
            subprocess.run([sys.executable, "-B", "-c", "import wheelbuild,sys; print(wheelbuild.build_wheel(sys.argv[1]))", str(wheels)], cwd=stage / project, check=True)
        report = Path(temp) / "resolve.json"
        subprocess.run([sys.executable, "-m", "pip", "install", "--dry-run", "--ignore-installed", "--disable-pip-version-check", "--no-index", "--only-binary=:all:", "--find-links", str(wheels), "--report", str(report), f"aivid-health-installer=={version}", f"aivid-health-platform-backend=={version}"], check=True, stdout=subprocess.DEVNULL)
        resolved = json.loads(report.read_text())["install"]
        selected, components, lines = set(), [], []
        from urllib.parse import unquote, urlsplit
        for item in resolved:
            name = Path(unquote(urlsplit(item["download_info"]["url"]).path)).name
            selected.add(name)
            md = item["metadata"]
            digest = sha(wheels / name)
            lines.append(f"{md['name']}=={md['version']} --hash=sha256:{digest}")
            components.append({"type": "library", "name": md["name"], "version": md["version"], "purl": f"pkg:pypi/{md['name'].lower().replace('_','-')}@{md['version']}", "hashes": [{"alg": "SHA-256", "content": digest}], "properties": [{"name": "aivid:wheel", "value": name}]})
        for file in wheels.glob("*.whl"):
            if file.name not in selected:
                file.unlink()
        (stage / "requirements.lock").write_text("\n".join(sorted(lines)) + "\n")
        components.append({"type": "application", "name": "CPython", "version": rt["python_version"], "hashes": [{"alg": "SHA-256", "content": rt["sha256"]}]})
        sbom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "metadata": {"component": {"type": "application", "name": "AIVID Health Monitor", "version": version}}, "components": components}
        (packaging / "cyclonedx.json").write_text(json.dumps(sbom, indent=2) + "\n")
        pub = packaging / "trusted-release-key.pem"
        pub.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        replacements = {"VERSION": version, "RUNTIME_FILE": rt["filename"], "RUNTIME_SHA256": rt["sha256"], "KEY_SHA256": sha(pub), "SIGNATURE_BYTES": str(key.key_size // 8)}
        bootstrap = (stage / "tools/bootstrap.sh.in").read_text()
        for k, v in replacements.items():
            bootstrap = bootstrap.replace("@@" + k + "@@", v)
        (stage / "tools/bootstrap.sh").write_text(bootstrap)
        for script, op in (("install.sh", "install"), ("prepare-cluster.sh", "prepare")):
            content = '#!/usr/bin/env bash\nset -Eeuo pipefail\nROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"\n'
            content += f'# Offline installer dependency: aivid-health-installer=={version}\n'
            content += f'exec bash "${{ROOT}}/tools/bootstrap.sh" {op} "$@"\n'
            (stage / script).write_text(content)
        for file in stage.rglob("*"):
            if file.is_file():
                file.chmod(0o755 if file.suffix == ".sh" else 0o644)
            else:
                file.chmod(0o755)
        files = [{"path": f.relative_to(stage).as_posix(), "sha256": sha(f), "size": f.stat().st_size, "mode": format(f.stat().st_mode & 0o777, "04o")} for f in sorted(stage.rglob("*")) if f.is_file()]
        manifest = {"product": "AIVID Health Monitor", "version": version, "build_id": a.build_id,
                    "runtime": "CPython " + rt["python_version"], "profile": "dashboard-peer-cluster",
                    "signature_algorithm": "RSA-PKCS1v15-SHA256", "files": files}
        raw = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
        (stage / "RELEASE_MANIFEST.json").write_bytes(raw)
        (stage / "RELEASE_MANIFEST.sig").write_bytes(key.sign(raw, padding.PKCS1v15(), hashes.SHA256()))
        sums = "\n".join(f"{sha(f)}  {f.relative_to(stage).as_posix()}" for f in sorted(stage.rglob("*")) if f.is_file()) + "\n"
        (stage / "SHA256SUMS").write_text(sums)
        (stage / "SHA256SUMS.sig").write_bytes(key.sign(sums.encode(), padding.PKCS1v15(), hashes.SHA256()))
        # Verify signature, dependency metadata and the actual final tree before packaging.
        key.public_key().verify((stage / "RELEASE_MANIFEST.sig").read_bytes(), raw, padding.PKCS1v15(), hashes.SHA256())
        key.public_key().verify((stage / "SHA256SUMS.sig").read_bytes(), sums.encode(), padding.PKCS1v15(), hashes.SHA256())
        subprocess.run([sys.executable, "-B", stage / "tools/verify_release.py", stage], check=True)
        for app in ("aivid_health_installer", "aivid_health_platform_backend"):
            wheel = next(wheels.glob(app + "-*.whl"))
            with zipfile.ZipFile(wheel) as z:
                md = BytesParser().parsebytes(z.read(next(n for n in z.namelist() if n.endswith("/METADATA"))))
                assert md["Version"] == version
        a.output.parent.mkdir(parents=True, exist_ok=True)
        with a.output.open("wb") as output, gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as gz, tarfile.open(fileobj=gz, mode="w") as archive:
            for file in [stage, *sorted(stage.rglob("*"))]:
                info = archive.gettarinfo(str(file), arcname=str(Path(stage.name) / file.relative_to(stage)))
                info.uid = info.gid = 0
                info.uname = info.gname = "root"
                info.mtime = 0
                if file.is_file():
                    with file.open("rb") as handle:
                        archive.addfile(info, handle)
                else:
                    archive.addfile(info)
    digest = sha(a.output)
    a.output.with_name(a.output.name + ".sha256").write_text(digest + "  " + a.output.name + "\n")
    print(json.dumps({"archive": str(a.output), "sha256": digest, "version": version, "build_id": a.build_id}, indent=2))


if __name__ == "__main__":
    main()
