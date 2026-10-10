"""Pipeline d'évènements : collecteurs -> moteur de règles -> base -> WebSocket / notifications."""
import asyncio
import hashlib
import json
import logging
import queue
import subprocess
import threading
import time

from . import db
from .config import AGENT_NAME
from .mitre import tactics_for
from .rules import RuleEngine

log = logging.getLogger("siem.bus")

engine = RuleEngine()
_q: "queue.Queue[dict]" = queue.Queue(maxsize=50000)
_ws_clients: set = set()
_loop: asyncio.AbstractEventLoop | None = None
_recent: dict[str, float] = {}
_alert_hooks = []  # callbacks(alert) — ex. réponse active
stats = {"events": 0, "alerts": 0, "dropped": 0, "started": time.time()}


def emit(event: dict):
    """Point d'entrée unique des collecteurs (thread-safe)."""
    event.setdefault("ts", time.time())
    event.setdefault("agent", AGENT_NAME)
    try:
        _q.put_nowait(event)
    except queue.Full:
        stats["dropped"] += 1


def set_loop(loop):
    global _loop
    _loop = loop


def register_ws(ws):
    _ws_clients.add(ws)


def unregister_ws(ws):
    _ws_clients.discard(ws)


def on_alert(cb):
    _alert_hooks.append(cb)


def _summary(ev: dict) -> str:
    for k in ("path", "cmdline", "remote", "message", "label", "title", "name"):
        v = ev.get(k)
        if v:
            return str(v)[:300]
    return ""


def _full_log(ev: dict) -> str:
    if ev.get("raw"):
        return str(ev["raw"])
    return json.dumps({k: v for k, v in ev.items() if k not in ("ts",)}, default=str, ensure_ascii=False)


async def _broadcast(payload: str):
    dead = []
    for ws in list(_ws_clients):
        try:
            await ws.send_text(payload)
        except Exception:
            dead.append(ws)
    for ws in dead:
        _ws_clients.discard(ws)


def _notify(alert):
    title = f"SentinelSIEM — niveau {alert['level']}"
    msg = alert["description"].replace('"', "'")[:200]
    try:
        subprocess.Popen(
            ["osascript", "-e", f'display notification "{msg}" with title "{title}" sound name "Basso"'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass


def _store(rule, ev):
    full = _full_log(ev)
    dedup_key = hashlib.sha1(f"{rule.id}|{full}".encode()).hexdigest()
    now = time.time()
    if now - _recent.get(dedup_key, 0) < 30:
        return None
    _recent[dedup_key] = now
    if len(_recent) > 5000:
        for k, t in list(_recent.items()):
            if now - t > 60:
                _recent.pop(k, None)

    mitre = list(rule.mitre)
    alert = {
        "ts": ev.get("ts", now),
        "rule_id": rule.id,
        "level": rule.level,
        "description": rule.render(ev),
        "module": ev.get("module", "unknown"),
        "groups": ",".join(rule.groups),
        "mitre": ",".join(mitre),
        "tactics": ",".join(tactics_for(mitre)),
        "agent": ev.get("agent", AGENT_NAME),
        "summary": _summary(ev),
        "full_log": full[:20000],
        "data": json.dumps(ev, default=str, ensure_ascii=False)[:50000],
        "status": "new",
    }
    cur = db.execute(
        "INSERT INTO alerts(ts, rule_id, level, description, module, groups, mitre, tactics, agent, summary, full_log, data, status)"
        " VALUES(:ts, :rule_id, :level, :description, :module, :groups, :mitre, :tactics, :agent, :summary, :full_log, :data, :status)",
        alert,
    )
    alert["id"] = cur.lastrowid
    return alert


def _worker():
    while True:
        ev = _q.get()
        stats["events"] += 1
        try:
            for rule, rev in engine.evaluate(ev):
                alert = _store(rule, rev)
                if not alert:
                    continue
                stats["alerts"] += 1
                if alert["level"] >= int(db.get_settings().get("notify_min_level", 10)):
                    _notify(alert)
                for cb in _alert_hooks:
                    try:
                        cb(alert, rev)
                    except Exception:
                        log.exception("hook d'alerte")
                if _loop and _ws_clients:
                    payload = json.dumps({"type": "alert", "alert": {k: v for k, v in alert.items() if k != "data"}})
                    asyncio.run_coroutine_threadsafe(_broadcast(payload), _loop)
        except Exception:
            log.exception("Erreur de traitement de l'évènement %s", ev)


def start():
    threading.Thread(target=_worker, name="bus", daemon=True).start()
