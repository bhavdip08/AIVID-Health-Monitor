# AIVID Health Monitor

Server resource monitoring and coordinated email alerts for 1 to 32 Linux servers.
The dashboard, pairing and all peer communication share **HTTPS TCP 8282**.

Read docs/RELEASE_NOTES.txt for changes, upgrade steps and compatibility.

This repository contains the complete source from build
`1.1.0-20261009.incidents1`, plus tests, manuals, release tools and the offline
dependency files needed to rebuild it. Application source matches that release.

## Features

- Host availability, CPU, RAM, local disk and NVIDIA GPU monitoring.
- Open and Closed / recovered incidents, lifecycle timelines, filters and pagination.
- Separate notification delivery log with accurate counts across retained history.
- Dashboard setup, server pairing and optional alert-sender priorities.
- One majority-elected SMTP sender with durable delivery records.
- Chosen dashboard login during installation and automatic network selection
  when only one eligible local address exists.
- Monitor data in `/opt/aivid-healthmonitor/data`.
- One HTTPS listener on 8282; SMTP connects outbound to the configured relay.

The monitor is a standalone systemd service. It does not manage Kubernetes
workloads, restart container runtimes or modify firewall rules.

## Repository contents

| Path | Contents |
| --- | --- |
| `backend/src/aivid_health/` | Monitoring, dashboard, HTTPS APIs, pairing, alert coordination and SMTP |
| `backend/src/aivid_health/static/` | Dashboard HTML, CSS and JavaScript |
| `installer/src/aivid_installer/` | Installer, setup and service-management commands |
| `tests/` | Unit and integration tests, fault-injection harnesses and benchmark |
| `tools/` | Offline build, signing, verification and installer packaging |
| `packaging/` | Bundled Python, pinned wheels, public verification key and systemd unit |
| `docs/` | Installation/user manuals, GitHub setup, development guide and verification report |

The original proprietary `LICENSE` is retained. Start with a private repository.
There are no deployment credentials, node databases or private signing keys in
this package. Password strings in tests are synthetic test fixtures.

## Install on a server

Use the signed `AIVID-Health-Monitor.run` and its matching
checksum, or build a new signed release using the development guide.

```bash
sha256sum -c AIVID-Health-Monitor.run.sha256
sudo bash AIVID-Health-Monitor.run
```

Open `https://SERVER_IP:8282`. Allow TCP 8282 between peers and from administrator
devices. See [the installation manual](docs/AIVID_Health_Monitor_Installation_Manual.docx)
and [the user manual](docs/AIVID_Health_Monitor_User_Manual.docx).

**A Git checkout is a development tree, not a signed installation package.**
The build tool generates new release manifests, signatures and checksums. Run
`install.sh` only from the resulting extracted signed release. Adding Git metadata
or editing a signed installation tree makes its strict file verification fail;
do not bypass that verification.

## Develop and test

See [the development guide](docs/DEVELOPMENT.md) for an offline setup, test
commands and signed-release builds. The shipped offline dependencies target
Linux x86_64 and CPython 3.12. The monitor's supported host installations are
Ubuntu 22.04/24.04 and Debian 12 with systemd.

[Release verification](docs/RELEASE_VERIFICATION.txt) describes the unit, interface
logic and three-node SMTP/lifecycle checks for this build. The report delivered
beside the installer includes packaged installation and upgrade checks. Browser
visual testing and production-host validation remain site checks.

## Push to your personal GitHub account

Follow [GitHub setup](docs/GITHUB_SETUP.md). Extract the source ZIP and push the
folder contents with Git. Do not upload just the ZIP or the `.run` as your source.
The bundled runtime is larger than GitHub's browser upload limit, so use Git.

## Alerting limits

Sending alerts requires a strict majority. One server cannot report its own
total failure; two servers cannot elect a sender with one offline. Directory
changes require all members online. SMTP cannot guarantee exactly-once inbox
delivery; uncertain submissions are held for review. Only NVIDIA GPU statistics
are collected in this build. See the manuals for operational details.

## Dashboard and email customization

Build `1.1.0-20261009.incidents1` uses the configured server names in the dashboard and emails. Immutable server keys remain internal for safe pairing and alert coordination. Login passwords have no minimum length (empty values accepted; maximum 256 characters); existing password hashes and accounts are retained.

On the current alert sender dashboard:

- **Appearance** edits the AIVID identity on the left and customer identity on the right. Both names and logos replicate to the cluster. The supplied AIVID vector is the default dashboard logo; mail embeds a PNG copy.
- **Email design** edits offline, recovery, resource and test subjects, heading, body, footer and accent color. Safe `{placeholders}` insert server names and event details into a professional HTML layout. A plain-text alternative is always included. Preview does not send mail.
- **Server setup** controls optional unique alert priorities. Blank uses registration order. Only the elected sender sends; in a three-node cluster server 2 reports server 1's outage while server 3 stays on standby.

Upgrade every member before saving the new shared branding or email options. Older SMTP/threshold settings gain defaults without discarding their values. Logo uploads are resized in the browser to keep replicated records small. No external fonts, scripts or hosted image services are used. The product still has exactly one HTTPS listener on TCP 8282.
