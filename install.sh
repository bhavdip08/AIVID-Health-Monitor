#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# Offline installer dependency: aivid-health-installer==1.1.0
exec bash "${ROOT}/tools/bootstrap.sh" install "$@"
