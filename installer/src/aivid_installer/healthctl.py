from __future__ import annotations
import argparse
import json
import subprocess
from pathlib import Path


def main(argv=None):
    p = argparse.ArgumentParser(prog="aivid-healthctl")
    p.add_argument("command", choices=["status", "start", "stop", "restart", "logs", "verify"])
    args = p.parse_args(argv)
    if args.command == "logs":
        return subprocess.call(["journalctl", "-u", "aivid-health", "-n", "100", "--no-pager"])
    if args.command == "verify":
        return subprocess.call(["/opt/aivid-health/current/venv/bin/aivid-monitor", "check"])
    return subprocess.call(["systemctl", args.command, "aivid-health.service"])


if __name__ == "__main__":
    raise SystemExit(main())
