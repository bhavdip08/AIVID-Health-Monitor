#!/usr/bin/env bash
# Read-only host diagnostics. Never installs packages or changes host permissions.
set -u
diagnose=false
[[ "${1:-}" == "--diagnose" ]] && diagnose=true
printf '%s\n' 'AIVID Health Monitor host check (read-only)'
uname -sm
openssl version
if [[ -r /etc/os-release ]]; then
  while IFS= read -r line; do
    case "$line" in ID=*|VERSION_ID=*|PRETTY_NAME=*) printf '%s\n' "$line";; esac
  done < /etc/os-release
fi
getconf GNU_LIBC_VERSION 2>/dev/null || true
if [[ "$diagnose" == true ]]; then
  for path in /opt /opt/aivid-health /opt/aivid-health/releases /opt/aivid-health/current/venv/bin/python /opt/aivid-healthmonitor /opt/aivid-healthmonitor/data /etc/aivid-health; do
    printf '\nPath: %s\n' "$path"
    namei -l -- "$path" 2>/dev/null || true
    if command -v findmnt >/dev/null; then findmnt -no TARGET,FSTYPE,OPTIONS -T "$path" 2>/dev/null || true; fi
    if command -v getfacl >/dev/null; then getfacl -p -- "$path" 2>/dev/null || true; fi
    if id aivid-health >/dev/null 2>&1 && [[ -e "$path" ]]; then
      if runuser -u aivid-health -- /usr/bin/test -x "$path"; then
        printf '%s\n' 'Service account execute/traverse check: OK'
      else
        printf '%s\n' 'Service account execute/traverse check: DENIED'
      fi
    fi
  done
  if command -v ss >/dev/null; then ss -ltnp '( sport = :8282 )' 2>/dev/null || true; fi
  if command -v systemctl >/dev/null; then
    systemctl show aivid-health.service -p LoadState -p ActiveState -p FragmentPath -p CPUQuotaPerSecUSec -p MemoryMax -p TasksMax 2>/dev/null || true
  fi
  printf '\n%s\n' 'No configuration files or passwords were read. No services or permissions were changed.'
  exit 0
fi
[[ "$(uname -m)" == x86_64 && "$(uname -s)" == Linux ]] || { echo 'Requires Linux x86_64.' >&2; exit 2; }
# /etc/os-release is a trusted, root-managed OS file.
. /etc/os-release
case "${ID:-}:${VERSION_ID:-}" in
  ubuntu:22.04|ubuntu:24.04|debian:12) ;;
  *) echo 'Unsupported host. This wheelhouse supports Ubuntu 22.04/24.04 and Debian 12 only; do not upgrade a production OS just to install this monitor. Supply --diagnose output for a matching build.' >&2; exit 2;;
esac
[[ -d /run/systemd/system ]] || { echo 'Host installation requires systemd. Use --prefix DIR --no-systemd only for isolated tests.' >&2; exit 2; }
for command in runuser systemctl groupadd useradd usermod; do
  command -v "$command" >/dev/null || { echo "Required host command missing: $command. Nothing has been installed." >&2; exit 2; }
done
printf '%s\n' 'Supported OS and host tools: OK'
