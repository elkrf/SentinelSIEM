"""Comptes utilisateurs, groupe admin, périphériques USB, volumes montés."""
import json
import os
import subprocess

from .base import Collector


def _run(args, timeout=30):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout).stdout
    except Exception:
        return ""


def list_users():
    out = _run(["/usr/bin/dscl", ".", "list", "/Users", "UniqueID"])
    users = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and not parts[0].startswith("_"):
            users.append({"name": parts[0], "uid": int(parts[1]) if parts[1].lstrip("-").isdigit() else parts[1]})
    return users


def admin_members():
    out = _run(["/usr/bin/dscl", ".", "-read", "/Groups/admin", "GroupMembership"])
    return sorted(out.replace("GroupMembership:", "").split())


def usb_devices():
    out = _run(["/usr/sbin/system_profiler", "SPUSBHostDataType", "-json"], timeout=60)
    devs = []
    try:
        data = json.loads(out)
    except Exception:
        return devs

    def walk(node):
        for it in node if isinstance(node, list) else [node]:
            if not isinstance(it, dict):
                continue
            name = it.get("_name")
            vid = it.get("USBKeyVendorID") or it.get("vendor_id")
            pid = it.get("USBKeyProductID") or it.get("product_id")
            serial = it.get("USBKeySerialNumber") or it.get("serial_num") or ""
            if name and (vid or pid):
                devs.append({"name": name, "vendor_id": str(vid), "product_id": str(pid), "serial": serial,
                             "vendor": it.get("USBKeyVendorName") or it.get("manufacturer", "")})
            for v in it.values():
                if isinstance(v, list):
                    walk(v)

    for v in data.values():
        walk(v)
    return devs


class SystemCollector(Collector):
    name = "system"
    title = "Comptes & périphériques"
    description = "Création de comptes, ajout au groupe admin, branchement de périphériques USB et montage de volumes."
    interval = 30

    def __init__(self):
        super().__init__()
        self.users = None
        self.admins = None
        self.usb = None
        self.volumes = None
        self.state = {}

    def tick(self):
        users = {u["name"]: u for u in list_users()}
        admins = set(admin_members())
        usb = {f'{d["vendor_id"]}:{d["product_id"]}:{d["serial"]}:{d["name"]}': d for d in usb_devices()}
        try:
            volumes = set(os.listdir("/Volumes"))
        except OSError:
            volumes = set()
        if self.users is not None:
            for n in users.keys() - self.users.keys():
                self.emit({"type": "user_created", "user": n, "uid": users[n]["uid"]})
            for n in self.users.keys() - users.keys():
                self.emit({"type": "user_deleted", "user": n})
            for n in admins - self.admins:
                self.emit({"type": "admin_added", "user": n})
            for n in self.admins - admins:
                self.emit({"type": "admin_removed", "user": n})
            for k in usb.keys() - self.usb.keys():
                self.emit({"type": "usb_connected", **usb[k]})
            for v in volumes - self.volumes:
                self.emit({"type": "volume_mounted", "name": v, "path": f"/Volumes/{v}"})
        self.users, self.admins, self.usb, self.volumes = users, admins, usb, volumes
        self.state = {"users": list(users.values()), "admins": sorted(admins), "usb": list(usb.values()),
                      "volumes": sorted(volumes)}
