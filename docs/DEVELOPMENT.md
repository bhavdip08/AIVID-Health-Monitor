# Development and signed release builds

Run development commands as your regular user in a separate working directory.
The supplied runtime and wheelhouse target Linux x86_64. Do not run test fixtures
against production monitor data.

## Prepare the offline development environment

From the repository root:

```bash
mkdir -p .build/python
tar -xzf packaging/runtime/cpython-3.12.13+20260718-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz \
  --strip-components=1 -C .build/python
.build/python/bin/python3 -m venv .venv
.venv/bin/python -m pip install --no-index --require-hashes \
  --find-links packaging/wheelhouse -r requirements.lock
.venv/bin/python -m pip check
```

This installs the bundled release wheels as the initial baseline. Use source
paths while testing edits, because those baseline wheels do not change when
you edit source files:

```bash
export PYTHONPATH="$PWD/backend/src:$PWD/installer/src"
export PYTHONDONTWRITEBYTECODE=1
.venv/bin/python -m unittest discover -s tests -p 'test_*.py' -q
```

For the existing integration suites, use fresh output directories each time:

```bash
.venv/bin/python tests/integration_dashboard.py .build/dashboard-test
.venv/bin/python tests/integration_cluster.py .build/smtp-test --automatic
```

These tests start local processes on distinct loopback IPs using TCP 8282. SMTP
tests use a separate local relay fixture and synthetic recipients. Keep TCP 8282
free for these tests. The installer suite must run separately from live tests.

## Build a signed offline release

The private key used for the delivered installer is intentionally not in this
repository. Use your own approved RSA-3072 release key, stored outside the checkout.
If creating a new signing identity, this command creates a new private key without
overwriting an existing file; keep its directory private:

```bash
mkdir -p "$HOME/.config/aivid-health-release"
chmod 700 "$HOME/.config/aivid-health-release"
.venv/bin/python - <<'PY'
import os
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
path = Path.home() / '.config/aivid-health-release/signing-key.pem'
key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
raw = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption())
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'wb') as file:
    file.write(raw)
print('Created private release key outside the repository')
PY
```

Preserve that key securely for future releases. A new key produces a new release
signing identity; communicate its public fingerprint through your trusted release
process. Node TLS certificates and release signing keys are separate identities.

**Build from a clean source export.** The builder rebuilds both application
wheels and generates the lockfile, SBOM, bootstrap, public key, signed manifest
and checksums. It excludes common generated files, but does not automatically
exclude every possible local developer directory. Export only tracked files so
that test state and local caches cannot enter the release.

Commit your changes first. Then use a unique build ID and a new export directory:

```bash
mkdir -p .build
mkdir .build/release-source-personal1
git archive --format=tar --output=.build/source-personal1.tar HEAD
tar -xf .build/source-personal1.tar -C .build/release-source-personal1
.venv/bin/python tools/build_release.py \
  --source .build/release-source-personal1 \
  --runtime-dir packaging/runtime \
  --wheelhouse packaging/wheelhouse \
  --signing-key "$HOME/.config/aivid-health-release/signing-key.pem" \
  --build-id 1.1.0-personal.1 \
  --output dist/aivid-health-1.1.0-personal.1.tar.gz
.venv/bin/python tools/build_easy_installer.py \
  dist/aivid-health-1.1.0-personal.1.tar.gz \
  dist/AIVID-Health-Monitor.run
```

Check each command succeeds before continuing. If you have no Git commit yet,
complete the initial commit in [GitHub setup](GITHUB_SETUP.md) first. Use a fresh
export directory and build ID for subsequent versions. Test the actual installer:

```bash
.venv/bin/python tests/integration_install.py \
  dist/AIVID-Health-Monitor.run .build/installer-test
```

Run `install.sh` only after extracting a generated signed release. Never weaken
verification to install an edited development checkout.
