AIVID HEALTH MONITOR 1.1.0
Build 1.1.0-20261009.incidents1 | 9 October 2026

Read docs/RELEASE_NOTES.txt for install and upgrade instructions.
Use the supplied AIVID-Health-Monitor.run and matching checksum.
This source tree contains build tools, runtime and pinned dependencies.
See README.md and docs/DEVELOPMENT.md to rebuild a signed release.

Open incidents remain open until confirmed recovery. Closed / recovered
contains the last 90 days of confirmed recoveries. Email delivery is a
separate log. Settings, history and server connections survive upgrades.

Linux x86_64: Ubuntu 22.04/24.04 and Debian 12 with systemd.
Ubuntu 20.04 is not supported by the bundled runtime dependency set.
Service actions target only aivid-health.service.
