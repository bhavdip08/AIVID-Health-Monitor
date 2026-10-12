from __future__ import annotations

import csv
import io
import shutil
import socket
import subprocess
import time

import psutil


def number(text):
    try:
        value = float(text.strip())
        return value if value == value and abs(value) != float("inf") else None
    except ValueError:
        return None


def gpu_sample():
    executable = shutil.which("nvidia-smi")
    if not executable:
        return {"status": "unavailable", "detail": "nvidia-smi is not installed", "devices": []}
    try:
        p = subprocess.run([executable, "--query-gpu=uuid,name,utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw", "--format=csv,noheader,nounits"], capture_output=True, text=True, timeout=4, check=False)
        if p.returncode:
            return {"status": "error", "detail": "NVIDIA driver query failed; check nvidia-smi on this server", "devices": []}
        rows = []
        for r in csv.reader(io.StringIO(p.stdout)):
            if len(r) != 7:
                raise ValueError("Invalid GPU response")
            used, total = number(r[3]), number(r[4])
            rows.append({"id": r[0].strip(), "name": r[1].strip(), "gpu_percent": number(r[2]),
                         "memory_used_mib": used, "memory_total_mib": total,
                         "gpu_memory_percent": used / total * 100 if used is not None and total else None,
                         "gpu_temperature": number(r[5]), "power_watts": number(r[6])})
        return {"status": "ok" if rows else "unavailable", "detail": "" if rows else "No NVIDIA GPUs reported", "devices": rows}
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return {"status": "error", "detail": "NVIDIA query timed out or returned invalid data", "devices": []}


def local_disks():
    """Mounted local filesystems only; avoid remote calls and container duplicates."""
    paths, devices = ['/'], set()
    remote = {'nfs', 'nfs4', 'cifs', 'smbfs', 'fuse.sshfs', 'autofs', '9p', 'ceph', 'glusterfs'}
    skip = ('/proc', '/sys', '/dev', '/run', '/snap', '/boot', '/var/lib/docker', '/var/lib/kubelet', '/var/lib/containers')
    try:
        parts = psutil.disk_partitions(all=False)
    except OSError:
        return paths
    for part in sorted(parts, key=lambda p: (p.mountpoint != '/', p.mountpoint)):
        if part.fstype in remote or part.fstype.startswith('fuse'):
            continue
        if any(part.mountpoint == x or part.mountpoint.startswith(x + '/') for x in skip):
            continue
        if part.device.startswith('/dev/loop') or part.device in devices:
            continue
        devices.add(part.device)
        if part.mountpoint not in paths:
            paths.append(part.mountpoint)
    return paths


class Collector:
    def __init__(self, config):
        self.config = config
        self.gpu_cache, self.gpu_at = None, 0
        self.disk_cache, self.disk_at = None, 0
        psutil.cpu_percent(interval=None)

    def collect(self):
        mem = psutil.virtual_memory()
        disks = []
        if self.config.data.get("disk_mode", "auto") == "auto":
            if self.disk_cache is None or time.monotonic() - self.disk_at >= 60:
                self.disk_cache, self.disk_at = local_disks(), time.monotonic()
            paths = self.disk_cache
        else:
            paths = self.config.disks
        for path in paths:
            try:
                d = psutil.disk_usage(path)
                disks.append({"path": path, "disk_percent": d.percent, "total_bytes": d.total, "free_bytes": d.free, "status": "ok"})
            except OSError:
                disks.append({"path": path, "disk_percent": None, "status": "error"})
        if self.gpu_cache is None or time.monotonic() - self.gpu_at >= 60:
            self.gpu_cache, self.gpu_at = gpu_sample(), time.monotonic()
        gpu = dict(self.gpu_cache)
        if self.config.data.get("gpu_required") and gpu["status"] == "unavailable":
            gpu["status"] = "error"
        return {"sampled_at": time.time(), "hostname": socket.gethostname(),
                "cpu_percent": psutil.cpu_percent(interval=None), "cpu_count": psutil.cpu_count(),
                "memory_percent": mem.percent, "memory_total_bytes": mem.total, "memory_available_bytes": mem.available,
                "swap_percent": psutil.swap_memory().percent, "uptime_seconds": max(0, time.time() - psutil.boot_time()),
                "disks": disks, "gpu": gpu}


def metrics(sample):
    """Return stable resource IDs. GPU UUIDs survive index changes."""
    result = {k: (k, sample.get(k)) for k in ("cpu_percent", "memory_percent")}
    for disk in sample.get("disks", []):
        result["disk:" + disk["path"]] = ("disk_percent", disk.get("disk_percent"))
        result["disk_read:" + disk["path"]] = ("sensor_error", disk.get("status") == "error")
    gpu = sample.get("gpu", {})
    result["gpu_driver"] = ("sensor_error", gpu.get("status") == "error")
    for device in gpu.get("devices", []):
        for k in ("gpu_percent", "gpu_memory_percent", "gpu_temperature"):
            result[k + ":" + device["id"]] = (k, device.get(k))
    return result
