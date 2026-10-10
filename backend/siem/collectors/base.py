import logging
import threading
import time
import traceback

from .. import bus

REGISTRY: dict[str, "Collector"] = {}


class Collector:
    name = "base"
    title = "Collecteur"
    description = ""
    interval = 60

    def __init__(self):
        self.status = "stopped"
        self.last_run = None
        self.last_error = None
        self.events = 0
        self.warnings: list[str] = []
        self._thread = None
        REGISTRY[self.name] = self
        self.log = logging.getLogger(f"siem.{self.name}")

    def emit(self, ev: dict):
        ev.setdefault("module", self.name)
        self.events += 1
        bus.emit(ev)

    def warn(self, msg: str):
        if msg not in self.warnings:
            self.warnings.append(msg)
            self.log.warning(msg)

    # Par défaut : boucle périodique sur tick()
    def setup(self):
        pass

    def tick(self):
        pass

    def run(self):
        self.setup()
        while True:
            try:
                self.tick()
                self.last_run = time.time()
                self.last_error = None
            except Exception as e:
                self.last_error = f"{type(e).__name__}: {e}"
                self.log.error(traceback.format_exc())
            time.sleep(self.interval)

    def _safe_run(self):
        self.status = "running"
        try:
            self.run()
        except Exception as e:
            self.last_error = f"{type(e).__name__}: {e}"
            self.log.error(traceback.format_exc())
        self.status = "stopped"

    def start(self):
        self._thread = threading.Thread(target=self._safe_run, name=self.name, daemon=True)
        self._thread.start()

    def info(self):
        return {
            "name": self.name, "title": self.title, "description": self.description,
            "status": self.status if (self._thread and self._thread.is_alive()) else "stopped",
            "last_run": self.last_run, "last_error": self.last_error, "events": self.events,
            "warnings": self.warnings, "interval": self.interval,
        }
