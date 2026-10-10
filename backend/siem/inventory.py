"""Inventaire système (syscollector) : matériel, OS, applications, paquets."""
import os
import platform
import plistlib
import subprocess
import time

import psutil

from .config import HOME

_cache: dict[str, tuple[float, object]] = {}


def _cached(key, ttl, fn):
    now = time.time()
    if key in _cache and now - _cache[key][0] < ttl:
        return _cache[key][1]
    v = fn()
    _cache[key] = (now, v)
    return v


def _sysctl(name):
    try:
        return subprocess.run(["/usr/sbin/sysctl", "-n", name], capture_output=True, text=True, timeout=5).stdout.strip()
    except Exception:
        return ""


def system_info():
    def f():
        vm = psutil.virtual_memory()
        du = psutil.disk_usage("/")
        ver = subprocess.run(["/usr/bin/sw_vers", "-productVersion"], capture_output=True, text=True).stdout.strip()
        build = subprocess.run(["/usr/bin/sw_vers", "-buildVersion"], capture_output=True, text=True).stdout.strip()
        ifaces = []
        for name, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if a.family.name in ("AF_INET",) and not a.address.startswith("127."):
                    ifaces.append({"iface": name, "ip": a.address})
        return {
            "hostname": platform.node(), "os": f"macOS {ver} ({build})", "kernel": platform.release(),
            "arch": platform.machine(), "model": _sysctl("hw.model"),
            "cpu": _sysctl("machdep.cpu.brand_string"), "cores": psutil.cpu_count(),
            "ram_total": vm.total, "disk_total": du.total, "boot_time": psutil.boot_time(),
            "interfaces": ifaces,
        }
    info = dict(_cached("system", 300, f))
    vm = psutil.virtual_memory()
    du = psutil.disk_usage("/")
    info.update({"cpu_percent": psutil.cpu_percent(interval=0.3), "ram_percent": vm.percent,
                 "disk_percent": du.percent, "disk_used": du.used, "load": os.getloadavg(),
                 "uptime": time.time() - info["boot_time"]})
    return info


def apps():
    def f():
        out = []
        for root in ("/Applications", str(HOME / "Applications"), "/Applications/Utilities"):
            try:
                names = os.listdir(root)
            except OSError:
                continue
            for n in names:
                if not n.endswith(".app"):
                    continue
                p = os.path.join(root, n)
                info = {}
                try:
                    with open(os.path.join(p, "Contents/Info.plist"), "rb") as fh:
                        info = plistlib.load(fh)
                except Exception:
                    pass
                out.append({
                    "name": n[:-4], "path": p, "version": str(info.get("CFBundleShortVersionString", "")),
                    "bundle_id": info.get("CFBundleIdentifier", ""), "mtime": os.path.getmtime(p),
                })
        return sorted(out, key=lambda x: x["name"].lower())
    return _cached("apps", 600, f)


def packages():
    def f():
        try:
            out = subprocess.run(["/opt/homebrew/bin/brew", "list", "--versions"], capture_output=True, text=True, timeout=60).stdout
        except Exception:
            return []
        res = []
        for line in out.splitlines():
            parts = line.split()
            if parts:
                res.append({"name": parts[0], "version": " ".join(parts[1:]), "source": "homebrew"})
        return res
    return _cached("packages", 600, f)


def app_signature(path):
    r = subprocess.run(["/usr/bin/codesign", "-dv", "--verbose=2", path], capture_output=True, text=True, timeout=30)
    auth = [l.split("=", 1)[1] for l in r.stderr.splitlines() if l.startswith("Authority=")]
    team = [l.split("=", 1)[1] for l in r.stderr.splitlines() if l.startswith("TeamIdentifier=")]
    notarized = subprocess.run(["/usr/sbin/spctl", "-a", "-vv", path], capture_output=True, text=True, timeout=30)
    return {"signed": r.returncode == 0, "authority": auth, "team": team[0] if team else "",
            "gatekeeper": (notarized.stderr or notarized.stdout).strip()}
