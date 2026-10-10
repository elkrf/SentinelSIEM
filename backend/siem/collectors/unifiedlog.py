"""Collecte des journaux unifiés macOS (log stream) : sudo, ssh, XProtect, Gatekeeper, authentification…"""
import json
import os
import re
import subprocess
import time

from .. import db
from .base import Collector

PREDICATE = " OR ".join([
    'process == "sudo"',
    'process == "su"',
    'process == "sshd"',
    'process == "sshd-session"',
    'process == "screensharingd"',
    'process == "XProtect"',
    'process == "XprotectService"',
    'process == "XProtectRemediator"',
    'subsystem == "com.apple.XProtectFramework.PluginAPI"',
    '(subsystem == "com.apple.syspolicy.exec" AND eventMessage CONTAINS[c] "deny")',
    '(process == "syspolicyd" AND eventMessage CONTAINS[c] "malware")',
    '(process == "loginwindow" AND (eventMessage CONTAINS "_numFailedAuthAttempts" OR eventMessage CONTAINS[c] "authentication failed" OR eventMessage CONTAINS[c] "incorrect password"))',
    '(process == "authd" AND (eventMessage CONTAINS[c] "Failed to authorize" OR eventMessage CONTAINS[c] "authentication failed"))',
    '(process == "opendirectoryd" AND eventMessage CONTAINS "Authentication failed for" AND eventMessage CONTAINS "CredentialsInvalid")',
    '(process == "screensaverengine" AND eventMessage CONTAINS[c] "fail")',
    '(process == "sysadminctl")',
    '(process == "dscl" )',
    '(process == "socketfilterfw" AND eventMessage CONTAINS[c] "disabled")',
])

RX_USER = [
    re.compile(r"^\s*(?P<user>[\w.\-]+)\s*:\s*(?:TTY|\d+ incorrect|user NOT|a password is required|command not allowed)"),
    re.compile(r"for (?:invalid user )?(?P<user>[\w.\-]+) from"),
    re.compile(r"[Uu]ser[:= ]+'?(?P<user>[\w.\-]+)'?"),
    re.compile(r"record:? ?'?(?P<user>[\w.\-]+)'?"),
]
RX_IP = re.compile(r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]{3,})", re.I)
RX_CMD = re.compile(r"COMMAND=(?P<cmd>.+)$")
RX_TARGET = re.compile(r"USER=(?P<target>[\w.\-]+)")


class UnifiedLogCollector(Collector):
    name = "logs"
    title = "Journaux macOS"
    description = "Flux temps réel du journal unifié macOS : sudo, SSH, XProtect, Gatekeeper, échecs d'authentification."

    def parse(self, obj: dict) -> dict:
        msg = obj.get("eventMessage", "") or ""
        proc = os.path.basename(obj.get("processImagePath", "") or "")
        ev = {
            "module": "logs",
            "type": "unified",
            "process": proc,
            "subsystem": obj.get("subsystem", ""),
            "category": obj.get("category", ""),
            "message": msg.strip(),
            "pid": obj.get("processID"),
            "log_level": obj.get("messageType", ""),
            "raw": f"{obj.get('timestamp', '')} {proc}[{obj.get('processID')}]: {msg.strip()}",
        }
        for rx in RX_USER:
            m = rx.search(msg)
            if m:
                ev["user"] = m.group("user")
                break
        m = RX_IP.search(msg)
        if m:
            ev["src_ip"] = m.group("ip")
        m = RX_CMD.search(msg)
        if m:
            ev["command"] = m.group("cmd").strip()
        m = RX_TARGET.search(msg)
        if m:
            ev["target_user"] = m.group("target")
        return ev

    def _consume(self, args):
        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
        for line in p.stdout:
            line = line.strip().rstrip(",")
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if obj.get("eventType") not in (None, "logEvent"):
                continue
            self.emit(self.parse(obj))
            self.last_run = time.time()
            if self.last_run - self._saved > 30:
                db.set_private("logs_last_ts", self.last_run)
                self._saved = self.last_run
        p.wait()
        return p.returncode

    def run(self):
        # Rattrapage : depuis le dernier arrêt (max 24 h) ou la dernière heure au premier démarrage
        self._saved = 0
        last = db.get_private("logs_last_ts")
        start = max(last or 0, time.time() - 86400) if last else time.time() - 3600
        try:
            self._consume(["/usr/bin/log", "show", "--style", "ndjson", "--start",
                           time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(start)), "--predicate", PREDICATE])
        except Exception as e:
            self.warn(f"log show: {e}")
        while True:
            rc = self._consume(["/usr/bin/log", "stream", "--style", "ndjson", "--level", "info", "--predicate", PREDICATE])
            self.last_error = f"log stream terminé (code {rc}), redémarrage…"
            time.sleep(5)
