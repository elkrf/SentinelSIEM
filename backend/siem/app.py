"""SentinelSIEM — API REST + WebSocket + console web."""
import asyncio
import csv
import io
import json
import logging
import os
import re
import threading
import time
from contextlib import asynccontextmanager
from logging.handlers import RotatingFileHandler

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import ai_note, auth, bus, db, inventory
from .explain import explain
from .collectors.base import REGISTRY
from .collectors.fim import FIMCollector
from .collectors.malware import MalwareScanner, delete_quarantined, eicar_bytes, quarantine_file, restore_file
from .collectors.network import NetworkCollector
from .collectors.persistence import PersistenceCollector
from .collectors.process import ProcessCollector, kill_process
from .collectors.sca import CHECKS, SCACollector, score as sca_score
from .collectors.system import SystemCollector
from .collectors.unifiedlog import UnifiedLogCollector
from .config import AGENT_NAME, BASE_DIR, FRONTEND_DIR, HOME, LOG_DIR
from .mitre import TACTICS, T as MITRE_T

# ------------------------------------------------------------------ logging
_h = RotatingFileHandler(LOG_DIR / "sentinel.log", maxBytes=5_000_000, backupCount=3)
_h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
logging.basicConfig(level=logging.INFO, handlers=[_h, logging.StreamHandler()])
log = logging.getLogger("siem")

# ------------------------------------------------------------------ collectors
scanner = MalwareScanner()
fim = FIMCollector(scanner)
procs = ProcessCollector(scanner)
net = NetworkCollector()
persist = PersistenceCollector()
system = SystemCollector()
sca = SCACollector()
sca.interval = 3600
logs_col = UnifiedLogCollector()


def _maintenance():
    while True:
        try:
            db.purge_old_alerts()
        except Exception:
            log.exception("purge")
        time.sleep(3600)


@asynccontextmanager
async def lifespan(app):
    bus.set_loop(asyncio.get_running_loop())
    bus.start()
    pw = auth.ensure_admin()
    if pw:
        log.warning("Compte admin créé — mot de passe dans data/admin_password.txt")
    for c in (scanner, fim, procs, net, persist, system, sca, logs_col):
        c.start()
    threading.Thread(target=_maintenance, daemon=True).start()
    bus.emit({"module": "siem", "type": "start", "agent": AGENT_NAME})
    yield


app = FastAPI(title="SentinelSIEM", lifespan=lifespan, docs_url="/api/docs", redoc_url=None)

PUBLIC = ("/login", "/api/login", "/static/", "/favicon")


@app.middleware("http")
async def auth_mw(request: Request, call_next):
    path = request.url.path
    if not path.startswith(PUBLIC):
        user = auth.user_for(request.cookies.get(auth.COOKIE))
        if not user:
            if path.startswith("/api/"):
                return JSONResponse({"detail": "Non authentifié"}, status_code=401)
            return RedirectResponse("/login")
        request.state.user = user
    resp = await call_next(request)
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


def _page(name):
    """Sert une page HTML en versionnant app.js / app.css (date de modification) pour que le
    navigateur recharge toujours l'interface après une mise à jour."""
    html = (FRONTEND_DIR / name).read_text()
    for asset in ("js/app.js", "css/app.css"):
        v = int((FRONTEND_DIR / asset).stat().st_mtime)
        html = html.replace(f"/static/{asset}\"", f"/static/{asset}?v={v}\"")
    return HTMLResponse(html, headers={"Cache-Control": "no-cache"})


@app.get("/")
def index():
    return _page("index.html")


@app.get("/login")
def login_page():
    return _page("login.html")


@app.get("/favicon.ico")
def favicon():
    return FileResponse(FRONTEND_DIR / "favicon.svg", media_type="image/svg+xml")


# ------------------------------------------------------------------ auth
class LoginBody(BaseModel):
    username: str
    password: str


@app.post("/api/login")
def api_login(body: LoginBody):
    if not auth.check(body.username, body.password):
        bus.emit({"module": "siem", "type": "auth_failed", "user": body.username})
        time.sleep(1)
        raise HTTPException(401, "Identifiants invalides")
    bus.emit({"module": "siem", "type": "auth_success", "user": body.username})
    tok = auth.login(body.username)
    r = JSONResponse({"ok": True})
    r.set_cookie(auth.COOKIE, tok, httponly=True, samesite="strict", max_age=auth.SESSION_TTL)
    return r


@app.post("/api/logout")
def api_logout(request: Request):
    auth.logout(request.cookies.get(auth.COOKIE))
    r = JSONResponse({"ok": True})
    r.delete_cookie(auth.COOKIE)
    return r


@app.get("/api/me")
def me(request: Request):
    return {"user": request.state.user, "agent": AGENT_NAME}


class PasswordBody(BaseModel):
    current: str
    new: str


@app.post("/api/password")
def change_password(body: PasswordBody, request: Request):
    if not auth.check(request.state.user, body.current):
        raise HTTPException(400, "Mot de passe actuel incorrect")
    if len(body.new) < 8:
        raise HTTPException(400, "8 caractères minimum")
    auth.set_password(request.state.user, body.new)
    f = BASE_DIR / "data" / "admin_password.txt"
    if f.exists():
        f.unlink()
    return {"ok": True}


# ------------------------------------------------------------------ requêtes d'alertes
LEVEL_CLASSES = [("critical", 12, 15), ("high", 7, 11), ("medium", 4, 6), ("low", 0, 3)]
TOKEN_RX = re.compile(r'(\w+)\s*(>=|<=|:|=|>|<)\s*("[^"]*"|\S+)')


def build_where(params: dict):
    where, args = ["1=1"], []
    since = params.get("since")
    hours = params.get("hours")
    if since:
        where.append("ts >= ?"); args.append(float(since))
    elif hours:
        where.append("ts >= ?"); args.append(time.time() - float(hours) * 3600)
    if params.get("until"):
        where.append("ts <= ?"); args.append(float(params["until"]))
    if params.get("module"):
        mods = params["module"].split(",")
        where.append(f"module IN ({','.join('?' * len(mods))})"); args += mods
    if params.get("min_level") not in (None, ""):
        where.append("level >= ?"); args.append(int(params["min_level"]))
    if params.get("max_level") not in (None, ""):
        where.append("level <= ?"); args.append(int(params["max_level"]))
    if params.get("rule_id"):
        where.append("rule_id = ?"); args.append(int(params["rule_id"]))
    if params.get("mitre"):
        where.append("(',' || mitre || ',') LIKE ?"); args.append(f"%,{params['mitre']}%")
    if params.get("tactic"):
        where.append("tactics LIKE ?"); args.append(f"%{params['tactic']}%")
    if params.get("status"):
        where.append("status = ?"); args.append(params["status"])
    if params.get("group"):
        where.append("(',' || groups || ',') LIKE ?"); args.append(f"%,{params['group']},%")
    q = (params.get("q") or "").strip()
    if q:
        # Langage de chasse : level>=10 module:fim rule:100201 mitre:T1110 group:ssh status:new "texte libre"
        free = TOKEN_RX.sub("", q).strip()
        for field, op, val in TOKEN_RX.findall(q):
            val = val.strip('"')
            f = field.lower()
            if f == "level" and val.isdigit():
                sqlop = {":": "=", "=": "="}.get(op, op)
                where.append(f"level {sqlop} ?"); args.append(int(val))
            elif f in ("module", "status", "agent"):
                where.append(f"{f} = ?"); args.append(val)
            elif f in ("rule", "rule_id") and val.isdigit():
                where.append("rule_id = ?"); args.append(int(val))
            elif f == "mitre":
                where.append("mitre LIKE ?"); args.append(f"%{val}%")
            elif f in ("group", "groups"):
                where.append("groups LIKE ?"); args.append(f"%{val}%")
            elif f == "tactic":
                where.append("tactics LIKE ?"); args.append(f"%{val}%")
            else:
                where.append("data LIKE ?"); args.append(f'%"{field}": %{val}%')
        for word in [w for w in free.split() if w]:
            where.append("(description LIKE ? OR full_log LIKE ? OR summary LIKE ?)")
            args += [f"%{word.strip(chr(34))}%"] * 3
    return " AND ".join(where), args


@app.get("/api/alerts")
def list_alerts(request: Request, limit: int = 100, offset: int = 0, sort: str = "ts", order: str = "desc"):
    p = dict(request.query_params)
    where, args = build_where(p)
    sort = sort if sort in ("ts", "level", "rule_id", "module") else "ts"
    order = "ASC" if order.lower() == "asc" else "DESC"
    total = db.query_one(f"SELECT COUNT(*) c FROM alerts WHERE {where}", args)["c"]
    items = db.query(
        f"SELECT id, ts, rule_id, level, description, module, groups, mitre, tactics, agent, summary, status "
        f"FROM alerts WHERE {where} ORDER BY {sort} {order}, id DESC LIMIT ? OFFSET ?",
        args + [min(limit, 1000), offset],
    )
    return {"total": total, "items": items}


@app.get("/api/alerts/export")
def export_alerts(request: Request, format: str = "csv"):
    where, args = build_where(dict(request.query_params))
    rows = db.query(f"SELECT * FROM alerts WHERE {where} ORDER BY ts DESC LIMIT 100000", args)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    if format == "json":
        for r in rows:
            r["data"] = json.loads(r["data"] or "{}")
        return StreamingResponse(io.BytesIO(json.dumps(rows, ensure_ascii=False, indent=1).encode()),
                                 media_type="application/json",
                                 headers={"Content-Disposition": f"attachment; filename=alerts-{stamp}.json"})
    buf = io.StringIO()
    w = csv.writer(buf)
    cols = ["id", "ts", "rule_id", "level", "description", "module", "groups", "mitre", "tactics", "agent", "summary", "status", "full_log"]
    w.writerow(["date"] + cols)
    for r in rows:
        w.writerow([time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["ts"]))] + [r[c] for c in cols])
    return StreamingResponse(io.BytesIO(buf.getvalue().encode("utf-8-sig")), media_type="text/csv",
                             headers={"Content-Disposition": f"attachment; filename=alerts-{stamp}.csv"})


def _bucket_for(hours):
    if hours <= 1:
        return 120
    if hours <= 24:
        return 3600
    if hours <= 168:
        return 6 * 3600
    return 86400


@app.get("/api/alerts/histogram")
def alerts_histogram(request: Request):
    p = dict(request.query_params)
    hours = float(p.get("hours") or 24)
    p["hours"] = hours
    where, args = build_where(p)
    now = time.time()
    bucket = _bucket_for(hours)
    since = now - hours * 3600
    start = since - (since % bucket)
    nb = int((now - start) // bucket) + 1
    series = {name: [0] * nb for name, _, _ in LEVEL_CLASSES}
    for r in db.query(f"SELECT CAST((ts - ?) / ? AS INTEGER) b, level, COUNT(*) c FROM alerts WHERE {where} GROUP BY b, level",
                      [start, bucket] + args):
        if 0 <= r["b"] < nb:
            for name, lo, hi in LEVEL_CLASSES:
                if lo <= r["level"] <= hi:
                    series[name][r["b"]] += r["c"]
    return {"labels": [start + i * bucket for i in range(nb)], "bucket": bucket, "series": series}


@app.get("/api/alerts/{aid}")
def get_alert(aid: int):
    r = db.query_one("SELECT * FROM alerts WHERE id=?", (aid,))
    if not r:
        raise HTTPException(404)
    r["data"] = json.loads(r["data"] or "{}")
    rule = bus.engine.by_id.get(r["rule_id"])
    r["rule"] = rule.to_dict() if rule else None
    r["mitre_details"] = [{"id": t, "name": MITRE_T.get(t, (t,))[0]} for t in (r["mitre"] or "").split(",") if t]
    try:
        r["note"] = explain(r, r["data"], rule)
    except Exception as e:
        log.warning("Explication de l'alerte %s impossible : %s", aid, e)
        r["note"] = None
    r["ai_note"] = db.query_one("SELECT ts, model, text FROM alert_ai_notes WHERE alert_id=?", (aid,))
    r["ai_available"] = bool(ai_note.claude_bin())
    return r


@app.post("/api/alerts/{aid}/ai")
def alert_ai(aid: int, refresh: bool = False):
    """Analyse approfondie par Claude (CLI `claude`, sans outils), mise en cache."""
    if not refresh:
        cached = db.query_one("SELECT ts, model, text FROM alert_ai_notes WHERE alert_id=?", (aid,))
        if cached:
            return cached
    a = get_alert(aid)
    try:
        text, model = ai_note.analyze(a)
    except RuntimeError as e:
        raise HTTPException(503, str(e))
    row = {"ts": time.time(), "model": model, "text": text}
    db.execute("INSERT OR REPLACE INTO alert_ai_notes(alert_id, ts, model, text) VALUES(?,?,?,?)", (aid, row["ts"], model, text))
    return row


class StatusBody(BaseModel):
    ids: list[int]
    status: str


@app.post("/api/alerts/status")
def set_status(body: StatusBody):
    if body.status not in ("new", "acknowledged", "resolved", "false_positive"):
        raise HTTPException(400, "Statut invalide")
    if body.ids:
        db.execute(f"UPDATE alerts SET status=? WHERE id IN ({','.join('?' * len(body.ids))})", [body.status] + body.ids)
    return {"ok": True}


@app.post("/api/alerts/status_all")
def set_status_all(request: Request, status: str = "acknowledged"):
    if status not in ("new", "acknowledged", "resolved", "false_positive"):
        raise HTTPException(400)
    p = dict(request.query_params)
    p.pop("status", None)
    where, args = build_where(p)
    db.execute(f"UPDATE alerts SET status=? WHERE {where}", [status] + args)
    return {"ok": True}


# ------------------------------------------------------------------ tableau de bord
@app.get("/api/stats/overview")
def overview(hours: float = 24):
    now = time.time()
    since = now - hours * 3600
    base = "FROM alerts WHERE ts >= ?"
    total = db.query_one(f"SELECT COUNT(*) c {base}", (since,))["c"]
    sev = {}
    for name, lo, hi in LEVEL_CLASSES:
        sev[name] = db.query_one(f"SELECT COUNT(*) c {base} AND level BETWEEN ? AND ?", (since, lo, hi))["c"]
    auth_fail = db.query_one(f"SELECT COUNT(*) c {base} AND groups LIKE '%authentication_failed%'", (since,))["c"]
    auth_ok = db.query_one(f"SELECT COUNT(*) c {base} AND groups LIKE '%authentication_success%'", (since,))["c"]
    malware = db.query_one(f"SELECT COUNT(*) c {base} AND module='malware' AND level >= 7", (since,))["c"]
    fim_c = db.query_one(f"SELECT COUNT(*) c {base} AND module='fim' AND level >= 3", (since,))["c"]
    unresolved = db.query_one(f"SELECT COUNT(*) c {base} AND status='new' AND level >= 7", (since,))["c"]

    bucket = _bucket_for(hours)
    start = since - (since % bucket)
    nb = int((now - start) // bucket) + 1
    series = {name: [0] * nb for name, _, _ in LEVEL_CLASSES}
    for r in db.query(f"SELECT CAST((ts - ?) / ? AS INTEGER) b, level, COUNT(*) c {base} GROUP BY b, level", (start, bucket, since)):
        b = r["b"]
        if 0 <= b < nb:
            for name, lo, hi in LEVEL_CLASSES:
                if lo <= r["level"] <= hi:
                    series[name][b] += r["c"]
    labels = [start + i * bucket for i in range(nb)]

    by_module = db.query(f"SELECT module, COUNT(*) c {base} GROUP BY module ORDER BY c DESC", (since,))
    top_rules = db.query(
        f"SELECT rule_id, MAX(level) level, COUNT(*) c, MAX(description) description {base} GROUP BY rule_id ORDER BY c DESC LIMIT 10", (since,))
    for r in top_rules:
        rule = bus.engine.by_id.get(r["rule_id"])
        if rule and "{" not in rule.description.split(":")[0].split("—")[0]:
            r["description"] = rule.description.split(":")[0].split("—")[0].strip()
    mitre_counts, tactic_counts = {}, {}
    for r in db.query(f"SELECT mitre, tactics {base} AND mitre != ''", (since,)):
        for t in r["mitre"].split(","):
            mitre_counts[t] = mitre_counts.get(t, 0) + 1
        for t in (r["tactics"] or "").split(","):
            if t:
                tactic_counts[t] = tactic_counts.get(t, 0) + 1
    top_mitre = sorted(({"id": k, "name": MITRE_T.get(k, (k,))[0], "c": v} for k, v in mitre_counts.items()), key=lambda x: -x["c"])[:10]
    recent = db.query(
        f"SELECT id, ts, rule_id, level, description, module, mitre, status {base} AND level >= 7 ORDER BY ts DESC LIMIT 12", (since,))
    levels = db.query(f"SELECT level, COUNT(*) c {base} GROUP BY level ORDER BY level", (since,))
    return {
        "total": total, "severity": sev, "auth_failures": auth_fail, "auth_success": auth_ok,
        "malware": malware, "fim": fim_c, "unresolved": unresolved, "sca": sca_score(),
        "quarantined": db.query_one("SELECT COUNT(*) c FROM quarantine WHERE status='quarantined'")["c"],
        "timeline": {"labels": labels, "bucket": bucket, "series": series},
        "by_module": by_module, "top_rules": top_rules, "top_mitre": top_mitre,
        "tactics": [{"name": n, "c": tactic_counts.get(n, 0)} for _, n in TACTICS],
        "recent": recent, "levels": levels,
        "bus": {**bus.stats, "uptime": now - bus.stats["started"]},
    }


@app.get("/api/mitre")
def mitre_matrix(hours: float = 720):
    since = time.time() - hours * 3600
    counts = {}
    for r in db.query("SELECT mitre, level FROM alerts WHERE ts >= ? AND mitre != ''", (since,)):
        for t in r["mitre"].split(","):
            c = counts.setdefault(t, {"count": 0, "max_level": 0})
            c["count"] += 1
            c["max_level"] = max(c["max_level"], r["level"])
    matrix = []
    for tid, tname in TACTICS:
        techs = []
        for t, (name, tactics) in MITRE_T.items():
            if tname in tactics:
                techs.append({"id": t, "name": name, **counts.get(t, {"count": 0, "max_level": 0})})
        techs.sort(key=lambda x: (-x["count"], x["id"]))
        matrix.append({"id": tid, "name": tname, "techniques": techs, "total": sum(x["count"] for x in techs)})
    return {"matrix": matrix}


# ------------------------------------------------------------------ FIM
@app.get("/api/fim")
def fim_info(q: str = "", limit: int = 200):
    rows = db.query(
        "SELECT * FROM fim_baseline WHERE path LIKE ? ORDER BY updated DESC LIMIT ?", (f"%{q}%", limit))
    per_root = []
    for r in fim.monitored():
        pre = r["path"].rstrip("/") + "/"
        if r["recursive"]:
            c = db.query_one("SELECT COUNT(*) c FROM fim_baseline WHERE path LIKE ?", (pre + "%",))["c"]
        else:
            c = db.query_one("SELECT COUNT(*) c FROM fim_baseline WHERE path LIKE ? AND path NOT LIKE ?", (pre + "%", pre + "%/%"))["c"]
        per_root.append({**r, "files": c})
    total = db.query_one("SELECT COUNT(*) c FROM fim_baseline")["c"]
    since = time.time() - 86400
    changes = {r["t"]: r["c"] for r in db.query(
        "SELECT json_extract(data,'$.type') t, COUNT(*) c FROM alerts WHERE module='fim' AND ts>=? GROUP BY t", (since,))}
    return {"total": total, "roots": per_root, "files": rows, "changes_24h": changes,
            "baseline_done": fim.baseline_done, "pending": len(fim.pending)}


# ------------------------------------------------------------------ malware
@app.get("/api/malware")
def malware_info():
    jobs = sorted(({k: v for k, v in j.items() if k != "cancel"} for j in scanner.jobs.values()),
                  key=lambda j: -j["started"])[:20]
    return {
        "clamav": scanner.clam_info(), "yara_rules": scanner.yara_count, "yara_error": scanner.yara_error,
        "scanned": scanner.scanned, "detections": scanner.detections, "queue": scanner.q.qsize(),
        "last_update": scanner.last_update, "update_running": scanner.update_running,
        "update_output": scanner.update_output, "jobs": jobs,
        "auto_quarantine": db.get_settings().get("auto_quarantine"),
        "scan_paths": db.get_settings().get("scan_paths"),
    }


class ScanBody(BaseModel):
    path: str


@app.post("/api/malware/scan")
def malware_scan(body: ScanBody):
    p = os.path.expanduser(body.path)
    if not os.path.exists(p):
        raise HTTPException(400, "Chemin introuvable")
    return scanner.start_job(p)


@app.post("/api/malware/scan/{jid}/cancel")
def malware_cancel(jid: str):
    j = scanner.jobs.get(jid)
    if j:
        j["cancel"] = True
    return {"ok": True}


@app.post("/api/malware/update")
def malware_update():
    threading.Thread(target=scanner.update_signatures, daemon=True).start()
    return {"ok": True}


@app.post("/api/malware/test")
def malware_test():
    """Dépose un fichier de test EICAR (inoffensif) pour valider la chaîne FIM → ClamAV/YARA → quarantaine."""
    for d in (HOME / "Downloads", "/Users/Shared"):
        try:
            p = os.path.join(str(d), f"sentinel-eicar-test-{int(time.time())}.com")
            with open(p, "wb") as f:
                f.write(eicar_bytes())
            scanner.maybe_scan(p, reason="test", force=True)
            return {"ok": True, "path": p}
        except PermissionError:
            continue
    raise HTTPException(500, "Impossible d'écrire le fichier de test")


@app.get("/api/quarantine")
def quarantine_list():
    return db.query("SELECT * FROM quarantine ORDER BY ts DESC LIMIT 500")


class FileBody(BaseModel):
    path: str


@app.post("/api/quarantine")
def quarantine_manual(body: FileBody, request: Request):
    p = os.path.expanduser(body.path)
    if not os.path.isfile(p):
        raise HTTPException(400, "Fichier introuvable")
    from .collectors.fim import sha256_file
    qid = quarantine_file(p, sha256_file(p), "Quarantaine manuelle", "manual")
    bus.emit({"module": "active_response", "type": "quarantine", "path": p, "signature": f"manuel ({request.state.user})", "quarantine_id": qid})
    return {"id": qid}


@app.post("/api/quarantine/{qid}/restore")
def quarantine_restore(qid: str, request: Request):
    try:
        dest = restore_file(qid)
    except ValueError as e:
        raise HTTPException(404, str(e))
    bus.emit({"module": "active_response", "type": "restore", "path": dest, "by": request.state.user})
    return {"ok": True, "path": dest}


@app.delete("/api/quarantine/{qid}")
def quarantine_delete(qid: str):
    try:
        delete_quarantined(qid)
    except ValueError as e:
        raise HTTPException(404, str(e))
    return {"ok": True}


# ------------------------------------------------------------------ SCA
@app.get("/api/sca")
def sca_results():
    rows = db.query("SELECT * FROM sca_results")
    order = {c[0]: i for i, c in enumerate(CHECKS)}
    rows.sort(key=lambda r: order.get(r["check_id"], 999))
    return {"checks": rows, "score": sca_score(), "running": sca.running, "last_run": sca.last_run}


@app.post("/api/sca/run")
def sca_run():
    threading.Thread(target=sca.run_checks, daemon=True).start()
    return {"ok": True}


# ------------------------------------------------------------------ inventaire
@app.get("/api/inventory/system")
def inv_system():
    return inventory.system_info()


@app.get("/api/inventory/processes")
def inv_processes():
    return procs.snapshot


@app.get("/api/inventory/network")
def inv_network():
    return net.snapshot


@app.get("/api/inventory/apps")
def inv_apps():
    return inventory.apps()


@app.get("/api/inventory/packages")
def inv_packages():
    return inventory.packages()


@app.get("/api/inventory/signature")
def inv_signature(path: str):
    return inventory.app_signature(path)


@app.get("/api/inventory/persistence")
def inv_persistence():
    return persist.inventory()


@app.get("/api/inventory/accounts")
def inv_accounts():
    return system.state


class KillBody(BaseModel):
    pid: int
    force: bool = False


@app.post("/api/response/kill")
def response_kill(body: KillBody, request: Request):
    if body.pid in (0, 1, os.getpid()):
        raise HTTPException(400, "Processus protégé")
    try:
        name = kill_process(body.pid, body.force)
    except Exception as e:
        raise HTTPException(400, f"Impossible de terminer le processus : {e}")
    bus.emit({"module": "active_response", "type": "kill", "pid": body.pid, "name": name, "by": request.state.user})
    return {"ok": True, "name": name}


# ------------------------------------------------------------------ règles & modules
@app.get("/api/rules")
def rules():
    counts = {r["rule_id"]: r["c"] for r in db.query("SELECT rule_id, COUNT(*) c FROM alerts GROUP BY rule_id")}
    out = bus.engine.all_rules()
    for r in out:
        r["alerts"] = counts.get(r["id"], 0)
    return out


@app.get("/api/rules/files")
def rule_files():
    from .config import RULES_DIR, YARA_DIR
    return {"rules": [{"name": f.name, "content": f.read_text()} for f in sorted(RULES_DIR.glob("*.yml"))],
            "yara": [{"name": f.name, "content": f.read_text()} for f in sorted(YARA_DIR.glob("*.yar"))]}


@app.post("/api/rules/reload")
def rules_reload():
    bus.engine.load()
    scanner.load_yara()
    return {"ok": True, "rules": len(bus.engine.by_id), "yara": scanner.yara_count, "yara_error": scanner.yara_error}


@app.get("/api/modules")
def modules():
    return {"modules": [c.info() for c in REGISTRY.values()], "bus": bus.stats, "agent": AGENT_NAME}


@app.get("/api/settings")
def get_settings():
    return db.get_settings()


@app.put("/api/settings")
async def put_settings(request: Request):
    body = await request.json()
    s = db.set_settings(body)
    bus.emit({"module": "siem", "type": "settings", "user": request.state.user, "keys": list(body.keys())})
    return s


@app.post("/api/system/restart")
def restart():
    def _exit():
        time.sleep(1)
        os._exit(0)  # launchd (KeepAlive) relance le service
    threading.Thread(target=_exit, daemon=True).start()
    return {"ok": True}


# ------------------------------------------------------------------ temps réel
@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    if not auth.user_for(ws.cookies.get(auth.COOKIE)):
        await ws.close(code=4401)
        return
    await ws.accept()
    bus.register_ws(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        bus.unregister_ws(ws)
