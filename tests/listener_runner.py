"""Test-only bind audit around the actual service entry point (no extra listener)."""
import json
from pathlib import Path
import socket
import sys

config, output = sys.argv[1:]
path = Path(output)
path.write_text('')


def audit(event, args):
    if event == 'socket.bind':
        sock, address = args
        if sock.family in (socket.AF_INET, socket.AF_INET6):
            with path.open('a') as log:
                log.write(json.dumps({'address': address, 'type': int(sock.type)}) + '\n')


sys.addaudithook(audit)
from aivid_health.cli import main
raise SystemExit(main(['serve', '--config', config]))
