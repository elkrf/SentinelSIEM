"""Surveillance des processus : nouvelles exécutions, lignes de commande suspectes, minage (CPU)."""
import os
import time

import psutil

from .. import db
from .base import Collector


class ProcessCollector(Collector):
    name = "process"
    title = "Surveillance des processus"
    description = "Détecte reverse shells, téléchargements piped-to-shell, vol d'identifiants, désactivation des protections, cryptomineurs…"

    def __init__(self, scanner=None):
        super().__init__()
        self.scanner = scanner
        self.known: dict[int, float] = {}
        self.high_cpu: dict[int, float] = {}
        self.cpu_alerted: set = set()
        self.scanned_exes: set = set()
        self.snapshot = []

    def setup(self):
        self.interval = int(db.get_settings().get("process_poll_interval", 3))

    def _event(self, p: psutil.Process, info: dict, etype="new"):
        cmd = info.get("cmdline") or []
        exe = info.get("exe") or ""
        try:
            parent = psutil.Process(info["ppid"]).name() if info.get("ppid") else ""
        except Exception:
            parent = ""
        return {
            "module": "process", "type": etype, "pid": info["pid"], "ppid": info.get("ppid"),
            "name": info.get("name") or "", "exe": exe, "cmdline": " ".join(cmd)[:4000],
            "user": info.get("username") or "", "parent": parent,
            "exe_dir": os.path.dirname(exe), "hidden": os.path.basename(exe).startswith("."),
        }

    def tick(self):
        threshold = float(db.get_settings().get("cpu_alert_threshold", 90))
        now = time.time()
        current = {}
        snap = []
        first = not self.known
        for p in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "username", "create_time", "cpu_percent", "memory_info"]):
            info = p.info
            pid = info["pid"]
            ct = info.get("create_time") or 0
            current[pid] = ct
            mem = info.get("memory_info")
            snap.append({
                "pid": pid, "ppid": info.get("ppid"), "name": info.get("name"), "exe": info.get("exe"),
                "user": info.get("username"), "cpu": info.get("cpu_percent") or 0.0,
                "mem": mem.rss if mem else 0, "started": ct,
                "cmdline": " ".join(info.get("cmdline") or [])[:500],
            })
            if self.known.get(pid) != ct:
                ev = self._event(p, info, "existing" if first else "new")
                self.emit(ev)
                exe = info.get("exe") or ""
                if self.scanner and exe and exe not in self.scanned_exes and self.scanner.in_risky_location(exe):
                    self.scanned_exes.add(exe)
                    self.scanner.maybe_scan(exe, reason="process", force=True)
            # Détection de consommation CPU anormale soutenue (cryptominage)
            cpu = info.get("cpu_percent") or 0.0
            if cpu >= threshold and pid not in (0, os.getpid()):
                start = self.high_cpu.setdefault(pid, now)
                if now - start > 120 and pid not in self.cpu_alerted:
                    self.cpu_alerted.add(pid)
                    ev = self._event(p, info, "high_cpu")
                    ev["cpu"] = round(cpu, 1)
                    ev["duration"] = int(now - start)
                    self.emit(ev)
            else:
                self.high_cpu.pop(pid, None)
        self.known = current
        for pid in list(self.cpu_alerted):
            if pid not in current:
                self.cpu_alerted.discard(pid)
        snap.sort(key=lambda x: -x["cpu"])
        self.snapshot = snap


def kill_process(pid: int, force=False):
    p = psutil.Process(pid)
    name = p.name()
    if force:
        p.kill()
    else:
        p.terminate()
    return name
