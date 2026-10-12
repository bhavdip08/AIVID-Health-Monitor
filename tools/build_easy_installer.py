#!/usr/bin/env python3
"""Wrap a verified offline release into one runnable, self-extracting file."""
import argparse
import hashlib
import json
import re
import tarfile
from pathlib import Path


def main():
    p = argparse.ArgumentParser()
    p.add_argument("archive", type=Path)
    p.add_argument("output", type=Path)
    args = p.parse_args()
    payload = args.archive.read_bytes()
    digest = hashlib.sha256(payload).hexdigest()
    with tarfile.open(args.archive, "r:gz") as archive:
        manifests = [m for m in archive.getmembers() if m.name.count("/") == 1 and m.name.endswith("/RELEASE_MANIFEST.json")]
        if len(manifests) != 1:
            p.error("Archive must contain one signed release root")
        root = manifests[0].name.split("/")[0]
        manifest = json.load(archive.extractfile(manifests[0]))
        if not re.fullmatch(r"aivid-health-enterprise-[A-Za-z0-9._-]+", root) or root != "aivid-health-enterprise-" + manifest["version"]:
            p.error("Archive root and release version disagree")
    header = r'''#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
# Lower the priority of this installer and its children only.
if command -v renice >/dev/null; then renice -n 10 -p "$$" >/dev/null 2>&1 || true; fi
if command -v ionice >/dev/null; then ionice -c 3 -p "$$" >/dev/null 2>&1 || true; fi
for cmd in tail sha256sum tar mktemp; do
  command -v "$cmd" >/dev/null || { echo "Required command missing: $cmd" >&2; exit 2; }
done
TEMP_DIR="$(mktemp -d -t aivid-easy.XXXXXXXX)"
trap 'rm -rf -- "${TEMP_DIR}"' EXIT
echo "AIVID Health Monitor — preparing dashboard installation"
tail -n +@@LINE@@ -- "$0" > "${TEMP_DIR}/release.tar.gz"
echo "@@HASH@@  ${TEMP_DIR}/release.tar.gz" | sha256sum --check --status || {
  echo "Installer is damaged. Download a fresh copy." >&2; exit 2;
}
tar -xzf "${TEMP_DIR}/release.tar.gz" -C "${TEMP_DIR}" --no-same-owner --same-permissions
bash "${TEMP_DIR}/@@ROOT@@/install.sh" "$@"
exit $?
__AIVID_ARCHIVE_BELOW__
'''
    header = header.replace("@@HASH@@", digest)
    header = header.replace("@@ROOT@@", root)
    header = header.replace("@@LINE@@", str(header.count("\n") + 1))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(header.encode() + payload)
    args.output.chmod(0o755)
    args.output.with_name(args.output.name + ".sha256").write_text(hashlib.sha256(args.output.read_bytes()).hexdigest() + "  " + args.output.name + "\n")
    print("Created " + str(args.output))


if __name__ == "__main__":
    main()
