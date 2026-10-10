"""Mécanismes de persistance : LaunchAgents, LaunchDaemons, crontab, fichiers de démarrage shell."""
import hashlib
import os
import plistlib
import subprocess
import time

from ..config import HOME
from .base import Collector

LAUNCH_DIRS = [
    (str(HOME / "Library/LaunchAgents"), "LaunchAgent utilisateur"),
    ("/Library/LaunchAgents", "LaunchAgent système"),
    ("/Library/LaunchDaemons", "LaunchDaemon système"),
]
SHELL_FILES = [".zshrc", ".zprofile", ".zshenv", ".zlogin", ".bashrc", ".bash_profile", ".profile"]


def _signed_by_apple_or_dev(path):
    try:
        r = subprocess.run(["/usr/bin/codesign", "-dv", "--verbose=2", path], capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            return "unsigned"
        auth = [l.split("=", 1)[1] for l in r.stderr.splitlines() if l.startswith("Authority=")]
        return auth[0] if auth else "adhoc"
    except Exception:
        return "unknown"


class PersistenceCollector(Collector):
    name = "persistence"
    title = "Persistance"
    description = "Inventaire et détection des nouveaux LaunchAgents/Daemons, tâches cron et scripts de démarrage shell."
    interval = 60

    def __init__(self):
        super().__init__()
        self.items: dict[str, dict] = {}
        self.first = True

    def _collect(self):
        items = {}
        for d, kind in LAUNCH_DIRS:
            try:
                names = os.listdir(d)
            except OSError:
                continue
            for fn in names:
                if not fn.endswith(".plist"):
                    continue
                p = os.path.join(d, fn)
                try:
                    with open(p, "rb") as f:
                        raw = f.read()
                    pl = plistlib.loads(raw)
                except Exception:
                    items[p] = {"path": p, "kind": kind, "label": fn, "program": "(illisible)", "hash": None}
                    continue
                args = pl.get("ProgramArguments") or []
                program = pl.get("Program") or (args[0] if args else "")
                items[p] = {
                    "path": p, "kind": kind, "label": pl.get("Label", fn),
                    "program": program, "arguments": " ".join(str(a) for a in args)[:2000],
                    "run_at_load": bool(pl.get("RunAtLoad")), "keep_alive": bool(pl.get("KeepAlive")),
                    "hash": hashlib.sha256(raw).hexdigest(), "disabled": bool(pl.get("Disabled")),
                }
        try:
            cron = subprocess.run(["/usr/bin/crontab", "-l"], capture_output=True, text=True, timeout=10).stdout
            for i, line in enumerate(l for l in cron.splitlines() if l.strip() and not l.strip().startswith("#")):
                key = f"crontab:{hashlib.sha1(line.encode()).hexdigest()[:10]}"
                items[key] = {"path": "crontab", "kind": "Tâche cron", "label": f"cron #{i+1}", "program": line,
                              "arguments": line, "hash": hashlib.sha256(line.encode()).hexdigest()}
        except Exception:
            pass
        for f in SHELL_FILES:
            p = str(HOME / f)
            if os.path.exists(p):
                try:
                    content = open(p, "rb").read()
                except OSError:
                    continue
                items[p] = {"path": p, "kind": "Script de démarrage shell", "label": f, "program": p,
                            "arguments": content.decode(errors="replace")[-2000:], "hash": hashlib.sha256(content).hexdigest()}
        return items

    def tick(self):
        cur = self._collect()
        for k, it in cur.items():
            old = self.items.get(k)
            if self.first:
                etype = "existing"
            elif old is None:
                etype = "new"
            elif old.get("hash") != it.get("hash"):
                etype = "modified"
            else:
                continue
            ev = {"module": "persistence", "type": etype, **it}
            prog = it.get("program") or ""
            if prog.startswith("/") and os.path.exists(prog) and it["kind"].startswith("Launch"):
                ev["signer"] = _signed_by_apple_or_dev(prog) if etype != "existing" or "/tmp" in prog or "/Users/Shared" in prog else ""
                ev["program_exists"] = True
            elif prog.startswith("/") and it["kind"].startswith("Launch"):
                ev["program_exists"] = False
            self.emit(ev)
        if not self.first:
            for k, it in self.items.items():
                if k not in cur:
                    self.emit({"module": "persistence", "type": "removed", **it})
        self.items = cur
        self.first = False

    def inventory(self):
        return sorted(self.items.values(), key=lambda x: (x["kind"], x["label"]))
