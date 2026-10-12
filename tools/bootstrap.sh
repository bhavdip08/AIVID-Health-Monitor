#!/usr/bin/env bash
# Generated from VERSION, wheel metadata and the runtime manifest. Do not edit a signed release.
set -Eeuo pipefail
umask 077
SOURCE_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
CALLER_PWD="${PWD}"
RUNTIME_FILE="cpython-3.12.13+20260718-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz"
RUNTIME_SHA256="5854aa6ec71cad00334d5065633c210b2e7feb40956767a59a91791cadcf0b79"
TRUSTED_KEY_SHA256="65fd703a47ceb163ec162ab6ae9d995e80a84e81c9dd3a8fb0dd1695e05a545d"
INSTALLER_REQUIREMENT="aivid-health-installer==1.1.0"
TEMP_ROOT=""
trap 'if [[ -n "${TEMP_ROOT}" ]]; then rm -rf -- "${TEMP_ROOT}"; fi' EXIT
trap 'echo "AIVID installation stopped at line ${LINENO}; no internet installation is attempted." >&2' ERR
for command in openssl sha256sum tar wc; do
  command -v "${command}" >/dev/null || { echo "Required command missing: ${command}" >&2; exit 2; }
done
[[ "$(uname -m)" == "x86_64" ]] || { echo "This package requires Linux x86_64." >&2; exit 2; }
[[ "$(uname -s)" == "Linux" ]] || { echo "This package requires Linux." >&2; exit 2; }
echo "[1/5] Verifying the release signature and file checksums"
cd -- "${SOURCE_ROOT}"
echo "${TRUSTED_KEY_SHA256}  packaging/trusted-release-key.pem" | sha256sum --check --status
for signature in SHA256SUMS.sig RELEASE_MANIFEST.sig; do
  [[ "$(wc -c < "${signature}")" -eq 384 ]] || { echo "Invalid signature length: ${signature}" >&2; exit 2; }
done
openssl dgst -sha256 -verify packaging/trusted-release-key.pem -signature SHA256SUMS.sig SHA256SUMS >/dev/null
openssl dgst -sha256 -verify packaging/trusted-release-key.pem -signature RELEASE_MANIFEST.sig RELEASE_MANIFEST.json >/dev/null
sha256sum --check --strict --status SHA256SUMS
echo "${RUNTIME_SHA256}  packaging/runtime/${RUNTIME_FILE}" | sha256sum --check --status
OPERATION="$1"
shift
if [[ "${OPERATION}" == "install" ]]; then
  if [[ "${1:-}" == "--diagnose" ]]; then
    exec bash tools/host-check.sh --diagnose
  fi
  ISOLATED=false
  for argument in "$@"; do
    case "${argument}" in --prefix|--prefix=*|--no-systemd|--help|-h) ISOLATED=true;; esac
  done
  if [[ "${ISOLATED}" == false ]]; then bash tools/host-check.sh; fi
fi
echo "[2/5] Extracting the bundled CPython runtime"
TEMP_ROOT="$(mktemp -d -t aivid-health-bootstrap.XXXXXXXX)"
mkdir "${TEMP_ROOT}/runtime"
tar -xzf "packaging/runtime/${RUNTIME_FILE}" -C "${TEMP_ROOT}/runtime" --strip-components=1 --no-same-owner
PYTHON="${TEMP_ROOT}/runtime/bin/python3"
"${PYTHON}" -I tools/verify_release.py "${SOURCE_ROOT}"
"${PYTHON}" -I -c 'import sys; assert sys.version_info[:2] == (3, 12)'
echo "[3/5] Installing pinned components from the offline wheelhouse (${INSTALLER_REQUIREMENT})"
"${PYTHON}" -I -m venv --copies "${TEMP_ROOT}/venv"
BOOTSTRAP_PYTHON="${TEMP_ROOT}/venv/bin/python"
"${BOOTSTRAP_PYTHON}" -I -m pip install --disable-pip-version-check --no-input --no-index --require-hashes --find-links "${SOURCE_ROOT}/packaging/wheelhouse" -r "${SOURCE_ROOT}/requirements.lock" >/dev/null
"${BOOTSTRAP_PYTHON}" -I -c 'import cryptography, psutil, pydantic_core; import aivid_installer.cli' || {
  echo 'Bundled dependency import failed. No system Python, OpenSSL, drivers or packages were changed.' >&2
  exit 2
}
echo "[4/5] Running the requested operation"
cd -- "${CALLER_PWD}"
if [[ "${OPERATION}" == "install" ]]; then
  "${TEMP_ROOT}/venv/bin/aivid-installer" --source "${SOURCE_ROOT}" "$@"
elif [[ "${OPERATION}" == "prepare" ]]; then
  "${TEMP_ROOT}/venv/bin/aivid-cluster-init" "$@"
else
  echo "Unknown bootstrap operation" >&2; exit 2
fi
echo "[5/5] Operation completed"
