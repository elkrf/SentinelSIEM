"""Moteur de règles façon Wazuh : niveaux 0-15, regex, corrélation par fréquence."""
import logging
import re
import threading
import time
from collections import defaultdict, deque

import yaml

from .config import RULES_DIR

log = logging.getLogger("siem.rules")


class _SafeDict(dict):
    def __missing__(self, key):
        return "?"


class Rule:
    def __init__(self, d: dict, source: str):
        self.id = int(d["id"])
        self.level = int(d.get("level", 3))
        self.description = d.get("description", f"Rule {self.id}")
        self.module = d.get("module")
        t = d.get("type")
        self.types = [t] if isinstance(t, str) else (t or [])
        self.match = {k: re.compile(str(v), re.I) for k, v in (d.get("match") or {}).items()}
        self.not_match = {k: re.compile(str(v), re.I) for k, v in (d.get("not_match") or {}).items()}
        self.mitre = d.get("mitre") or []
        self.groups = d.get("groups") or []
        self.if_matched_sid = d.get("if_matched_sid")
        self.frequency = int(d.get("frequency", 0))
        self.timeframe = int(d.get("timeframe", 60))
        self.same_field = d.get("same_field")
        self.enabled = d.get("enabled", True)
        self.source = source
        self.hits = 0

    @property
    def is_correlation(self):
        return self.if_matched_sid is not None

    def matches(self, ev: dict) -> bool:
        if self.module and ev.get("module") != self.module:
            return False
        if self.types and ev.get("type") not in self.types:
            return False
        for field, rx in self.match.items():
            v = ev.get(field)
            if v is None or not rx.search(str(v)):
                return False
        for field, rx in self.not_match.items():
            v = ev.get(field)
            if v is not None and rx.search(str(v)):
                return False
        return True

    def render(self, ev: dict) -> str:
        try:
            return self.description.format_map(_SafeDict({k: v for k, v in ev.items() if v is not None}))
        except Exception:
            return self.description

    def to_dict(self):
        return {
            "id": self.id, "level": self.level, "description": self.description, "module": self.module,
            "types": self.types, "mitre": self.mitre, "groups": self.groups, "source": self.source,
            "correlation": self.is_correlation, "frequency": self.frequency, "timeframe": self.timeframe,
            "if_matched_sid": self.if_matched_sid, "same_field": self.same_field, "hits": self.hits,
            "enabled": self.enabled,
            "match": {k: v.pattern for k, v in self.match.items()},
        }


class RuleEngine:
    def __init__(self):
        self.lock = threading.Lock()
        self.base_rules: list[Rule] = []
        self.correlation: dict[int, list[Rule]] = defaultdict(list)
        self.by_id: dict[int, Rule] = {}
        self.windows: dict[tuple, deque] = defaultdict(deque)
        self.load()

    def load(self):
        base, corr, by_id = [], defaultdict(list), {}
        for f in sorted(RULES_DIR.glob("*.y*ml")):
            try:
                items = yaml.safe_load(f.read_text()) or []
            except Exception as e:
                log.error("Erreur de chargement %s: %s", f, e)
                continue
            for d in items:
                try:
                    r = Rule(d, f.name)
                except Exception as e:
                    log.error("Règle invalide dans %s: %s (%s)", f, d, e)
                    continue
                if not r.enabled:
                    continue
                old = by_id.get(r.id)
                if old:  # une règle locale écrase une règle par défaut de même id
                    if old in base:
                        base.remove(old)
                by_id[r.id] = r
                if r.is_correlation:
                    corr[int(r.if_matched_sid)].append(r)
                else:
                    base.append(r)
        with self.lock:
            self.base_rules, self.correlation, self.by_id = base, corr, by_id
        log.info("%d règles chargées (%d de corrélation)", len(by_id), sum(len(v) for v in corr.values()))

    def evaluate(self, ev: dict) -> list[tuple[Rule, dict]]:
        """Retourne la liste des (règle, évènement) déclenchées."""
        with self.lock:
            best = None
            for r in self.base_rules:
                if r.matches(ev) and (best is None or r.level > best.level):
                    best = r
            if best is None:
                return []
            best.hits += 1
            fired = [(best, ev)]
            now = time.time()
            for cr in self.correlation.get(best.id, []):
                key_val = ev.get(cr.same_field) if cr.same_field else "*"
                key = (cr.id, key_val)
                win = self.windows[key]
                win.append(now)
                while win and now - win[0] > cr.timeframe:
                    win.popleft()
                if len(win) >= cr.frequency:
                    win.clear()
                    cr.hits += 1
                    cev = dict(ev)
                    cev["correlated_count"] = cr.frequency
                    cev["correlated_rule"] = best.id
                    fired.append((cr, cev))
            return fired

    def all_rules(self):
        with self.lock:
            return sorted((r.to_dict() for r in self.by_id.values()), key=lambda x: x["id"])
