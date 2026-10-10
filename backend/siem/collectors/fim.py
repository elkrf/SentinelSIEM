"""File Integrity Monitoring : baseline SHA-256 + surveillance temps réel FSEvents."""
import grp
import hashlib
import os
import pwd
import re
import stat
import threading
import time

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from .. import db
from ..config import BASE_DIR
from .base import Collector

MAX_HASH = 100 * 1024 * 1024
MAX_FILES_PER_ROOT = 30000


def sha256_file(path, limit=MAX_HASH):
    try:
        if os.path.getsize(path) > limit:
            return None
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


def file_meta(path):
    try:
        st = os.lstat(path)
    except OSError:
        return None
    try:
        owner = pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        owner = str(st.st_uid)
    try:
        group = grp.getgrgid(st.st_gid).gr_name
    except KeyError:
        group = str(st.st_gid)
    return {
        "size": st.st_size, "mtime": st.st_mtime, "mode": stat.S_IMODE(st.st_mode),
        "perm": stat.filemode(st.st_mode), "owner": owner, "group": group,
        "is_dir": stat.S_ISDIR(st.st_mode), "is_link": stat.S_ISLNK(st.st_mode),
        "is_exec": bool(st.st_mode & 0o111) and stat.S_ISREG(st.st_mode),
    }


class _Handler(FileSystemEventHandler):
    def __init__(self, col, root, recursive):
        self.col, self.root, self.recursive = col, root, recursive

    def _accept(self, path):
        if not self.recursive and os.path.dirname(path.rstrip("/")) != self.root:
            return False
        return True

    def on_any_event(self, event):
        if event.event_type in ("opened", "closed", "closed_no_write"):
            return
        paths = [event.src_path]
        if event.event_type == "moved":
            paths = [event.src_path, event.dest_path]
        for p in paths:
            if self._accept(p):
                self.col.pending[p] = (time.time(), event.is_directory)


class FIMCollector(Collector):
    name = "fim"
    title = "Intégrité des fichiers (FIM)"
    description = "Empreintes SHA-256 et surveillance temps réel des répertoires sensibles (LaunchAgents, /etc, .ssh, Téléchargements…)."

    def __init__(self, scanner=None):
        super().__init__()
        self.scanner = scanner
        self.pending: dict[str, tuple] = {}
        self.observer = None
        self.ignore = []
        self.roots = []
        self.baseline_done = False
        self.baseline_count = 0

    def _ignored(self, path):
        if path.startswith(str(BASE_DIR)):
            return True
        return any(rx.search(path) for rx in self.ignore)

    def _root_for(self, path):
        for r in self.roots:
            if path == r["path"] or path.startswith(r["path"].rstrip("/") + "/"):
                return r
        return None

    # ----------------------------------------------------------- baseline
    def _baseline(self):
        known = {r["path"]: r for r in db.query("SELECT path, size, mtime FROM fim_baseline")}
        first_time = not known
        seen = set()
        rows = []
        for r in self.roots:
            root = r["path"]
            if not os.path.isdir(root):
                continue
            count = 0
            try:
                if r["recursive"]:
                    walker = os.walk(root)
                else:
                    entries = os.listdir(root)
                    walker = [(root, [], entries)]
                for dirpath, dirnames, filenames in walker:
                    dirnames[:] = [d for d in dirnames if not d.endswith(".app") and not d.startswith(".Trash")]
                    for fn in filenames:
                        p = os.path.join(dirpath, fn)
                        if self._ignored(p):
                            continue
                        m = file_meta(p)
                        if not m:
                            continue
                        if p in known:
                            seen.add(p)
                            k = known[p]
                            if k["size"] != m["size"] or abs((k["mtime"] or 0) - m["mtime"]) > 0.001:
                                self.pending[p] = (0, m["is_dir"])  # modifié pendant l'arrêt du SIEM
                            continue
                        sha = None if m["is_dir"] else sha256_file(p, 50 * 1024 * 1024)
                        rows.append((p, sha, m["size"], m["mtime"], m["mode"], m["owner"], int(m["is_dir"]), time.time()))
                        count += 1
                        if count >= MAX_FILES_PER_ROOT:
                            break
                    if count >= MAX_FILES_PER_ROOT:
                        self.warn(f"Limite de {MAX_FILES_PER_ROOT} fichiers atteinte pour {root}")
                        break
            except PermissionError:
                self.warn(f"Accès refusé à {root} — accordez l'« Accès complet au disque » à Python (voir README).")
        if not first_time:
            for p in known:
                if p not in seen and not os.path.lexists(p) and self._root_for(p):
                    self.pending[p] = (0, False)  # supprimé pendant l'arrêt du SIEM
        if rows and not first_time:
            # Nouveaux fichiers apparus pendant l'arrêt : traités comme des ajouts
            for row in rows:
                self.pending[row[0]] = (0, bool(row[6]))
            rows = []
        if rows:
            db.executemany(
                "INSERT OR REPLACE INTO fim_baseline(path, sha256, size, mtime, mode, owner, is_dir, updated) VALUES(?,?,?,?,?,?,?,?)",
                rows,
            )
        self.baseline_count = db.query_one("SELECT COUNT(*) c FROM fim_baseline")["c"]
        self.baseline_done = True
        self.emit({"module": "fim", "type": "baseline", "count": self.baseline_count, "first": first_time,
                   "message": f"Baseline FIM : {self.baseline_count} fichiers indexés"})

    # ----------------------------------------------------------- changes
    def _process(self, path, is_dir):
        if self._ignored(path):
            return
        root = self._root_for(path)
        old = db.query_one("SELECT * FROM fim_baseline WHERE path=?", (path,))
        meta = file_meta(path)
        base = {
            "module": "fim", "path": path, "filename": os.path.basename(path),
            "directory": os.path.dirname(path), "root": root["path"] if root else "",
            "ext": os.path.splitext(path)[1].lower(),
        }
        if meta is None:
            if old:
                db.execute("DELETE FROM fim_baseline WHERE path=?", (path,))
                self.emit({**base, "type": "deleted", "old_sha256": old["sha256"], "size": old["size"]})
            return
        if meta["is_dir"] and root and root["recursive"]:
            return
        sha = None if meta["is_dir"] else sha256_file(path)
        ev = {**base, "sha256": sha, "size": meta["size"], "perm": meta["perm"], "owner": meta["owner"],
              "group": meta["group"], "is_exec": meta["is_exec"], "is_dir": meta["is_dir"],
              "hidden": os.path.basename(path).startswith(".")}
        db.execute(
            "INSERT OR REPLACE INTO fim_baseline(path, sha256, size, mtime, mode, owner, is_dir, updated) VALUES(?,?,?,?,?,?,?,?)",
            (path, sha, meta["size"], meta["mtime"], meta["mode"], meta["owner"], int(meta["is_dir"]), time.time()),
        )
        if not old:
            self.emit({**ev, "type": "added"})
        else:
            changes = []
            if old["sha256"] != sha and not meta["is_dir"]:
                changes.append("contenu")
            if old["mode"] != meta["mode"]:
                changes.append("permissions")
                ev["old_perm"] = stat.filemode(old["mode"] | (stat.S_IFDIR if old["is_dir"] else stat.S_IFREG))
            if old["owner"] != meta["owner"]:
                changes.append("propriétaire")
                ev["old_owner"] = old["owner"]
            if not changes:
                return
            ev["old_sha256"] = old["sha256"]
            ev["changes"] = ", ".join(changes)
            self.emit({**ev, "type": "modified"})
        if self.scanner and not meta["is_dir"]:
            self.scanner.maybe_scan(path, reason="fim")

    def _drain(self):
        while True:
            time.sleep(1)
            now = time.time()
            ready = [(p, d) for p, (t, d) in list(self.pending.items()) if now - t > 1.5]
            for p, d in ready:
                self.pending.pop(p, None)
                try:
                    self._process(p, d)
                except Exception as e:
                    self.last_error = str(e)
            if ready:
                self.last_run = now

    def run(self):
        s = db.get_settings()
        self.ignore = [re.compile(x) for x in s.get("fim_ignore", [])]
        self.roots = []
        for r in s.get("fim_paths", []):
            p = os.path.realpath(os.path.expanduser(r["path"]))
            if os.path.isdir(p):
                self.roots.append({"path": p, "recursive": bool(r.get("recursive"))})
        # Les racines les plus spécifiques d'abord
        self.roots.sort(key=lambda r: -len(r["path"]))
        self.observer = Observer()
        for r in self.roots:
            try:
                self.observer.schedule(_Handler(self, r["path"], r["recursive"]), r["path"], recursive=r["recursive"])
            except Exception as e:
                self.warn(f"Impossible de surveiller {r['path']}: {e}")
        self.observer.start()
        threading.Thread(target=self._drain, daemon=True, name="fim-drain").start()
        self._baseline()
        self.last_run = time.time()
        while True:
            time.sleep(3600)

    def monitored(self):
        return self.roots
