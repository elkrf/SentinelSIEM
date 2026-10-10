"""Surveillance réseau : ports en écoute, connexions sortantes, ports C2 / minage, IOC IP."""
import ipaddress
import re
import subprocess
import time

from .. import db
from .base import Collector

RX = re.compile(r"^(?P<cmd>\S+)\s+(?P<pid>\d+)\s+(?P<user>\S+)\s+\S+\s+(?P<type>IPv[46])\s+\S+\s+\S+\s+(?P<proto>TCP|UDP)\s+(?P<name>.+)$")


def _split(addr):
    if addr.startswith("["):
        host, _, port = addr[1:].partition("]:")
    else:
        host, _, port = addr.rpartition(":")
    return host, port


def _is_public(ip):
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified)
    except ValueError:
        return False


class NetworkCollector(Collector):
    name = "network"
    title = "Surveillance réseau"
    description = "Ports en écoute, connexions établies, détection de ports C2/minage et d'adresses IP malveillantes (IOC)."

    def __init__(self):
        super().__init__()
        self.listening: set = set()
        self.seen_conn: set = set()
        self.first = True
        self.snapshot = {"listening": [], "established": []}

    def setup(self):
        self.interval = int(db.get_settings().get("network_poll_interval", 15))

    def _lsof(self):
        try:
            out = subprocess.run(["/usr/sbin/lsof", "-nP", "-iTCP", "-iUDP", "+c", "0"],
                                 capture_output=True, text=True, timeout=30).stdout
        except Exception as e:
            self.last_error = str(e)
            return []
        rows = []
        for line in out.splitlines()[1:]:
            m = RX.match(line)
            if not m:
                continue
            d = m.groupdict()
            name = d["name"]
            state = ""
            sm = re.search(r"\((\w+)\)$", name)
            if sm:
                state = sm.group(1)
                name = name[: sm.start()].strip()
            local, _, remote = name.partition("->")
            lh, lp = _split(local)
            rows.append({
                "process": d["cmd"].replace("\\x20", " "), "pid": int(d["pid"]), "user": d["user"], "proto": d["proto"],
                "family": d["type"], "local": local, "local_host": lh, "local_port": lp,
                "remote": remote, "state": state or ("LISTEN" if d["proto"] == "UDP" and not remote else ""),
            })
        return rows

    def tick(self):
        s = db.get_settings()
        sus_ports = {str(p) for p in s.get("suspicious_ports", [])}
        ioc_ips = set(s.get("ioc_ips", []))
        rows = self._lsof()
        listening, established = [], []
        cur_listen = set()
        for r in rows:
            if r["proto"] == "TCP" and r["state"] == "LISTEN":
                listening.append(r)
                key = (r["process"], r["local_port"], r["proto"])
                cur_listen.add(key)
                if not self.first and key not in self.listening:
                    self.emit({"module": "network", "type": "listen_new", **r,
                               "exposed": r["local_host"] in ("*", "0.0.0.0", "::", "[::]")})
            elif r["remote"]:
                established.append(r)
                rh, rp = _split(r["remote"])
                r["remote_ip"], r["remote_port"] = rh, rp
                ckey = (r["pid"], r["remote"])
                if ckey in self.seen_conn:
                    continue
                self.seen_conn.add(ckey)
                ev = {"module": "network", "type": "connection", **r, "public": _is_public(rh)}
                if rh in ioc_ips:
                    ev["ioc"] = "ip"
                if rp in sus_ports:
                    ev["suspicious_port"] = True
                self.emit(ev)
        self.listening = cur_listen if not self.first else cur_listen
        self.first = False
        if len(self.seen_conn) > 20000:
            self.seen_conn.clear()
        self.snapshot = {"listening": listening, "established": established, "ts": time.time()}
