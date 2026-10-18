"""Configuration globale de SentinelSIEM."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = BASE_DIR / "data"
QUARANTINE_DIR = DATA_DIR / "quarantine"
LOG_DIR = DATA_DIR / "logs"
DB_PATH = DATA_DIR / "siem.db"
RULES_DIR = BASE_DIR / "rules"
YARA_DIR = BASE_DIR / "yara"
FRONTEND_DIR = BASE_DIR / "frontend"
HOME = Path.home()

HOST = os.environ.get("SIEM_HOST", "127.0.0.1")
PORT = int(os.environ.get("SIEM_PORT", "5601"))

CLAMD_SOCKET = "/opt/homebrew/var/run/clamav/clamd.sock"
CLAMSCAN_BIN = "/opt/homebrew/bin/clamscan"
FRESHCLAM_BIN = "/opt/homebrew/bin/freshclam"

AGENT_NAME = os.uname().nodename.split(".")[0]

for d in (DATA_DIR, QUARANTINE_DIR, LOG_DIR):
    d.mkdir(parents=True, exist_ok=True)


def _h(p: str) -> str:
    return str(HOME / p)


DEFAULT_SETTINGS = {
    "auto_quarantine": True,
    "notify_min_level": 10,
    "retention_days": 30,
    "process_poll_interval": 3,
    "network_poll_interval": 15,
    "cpu_alert_threshold": 90,
    "max_scan_size_mb": 200,
    # Répertoires surveillés par le FIM (File Integrity Monitoring)
    "fim_paths": [
        {"path": _h("Library/LaunchAgents"), "recursive": False},
        {"path": "/Library/LaunchAgents", "recursive": False},
        {"path": "/Library/LaunchDaemons", "recursive": False},
        {"path": "/private/etc", "recursive": False},
        {"path": _h(".ssh"), "recursive": True},
        {"path": str(HOME), "recursive": False},
        {"path": _h("Downloads"), "recursive": True},
        {"path": _h("Desktop"), "recursive": True},
        {"path": "/Applications", "recursive": False},
        {"path": "/usr/local/bin", "recursive": False},
        {"path": "/Users/Shared", "recursive": True},
        {"path": "/private/tmp", "recursive": False},
    ],
    # Tout fichier créé/modifié ici est analysé par ClamAV + YARA
    "scan_paths": [
        _h("Downloads"), _h("Desktop"), "/Users/Shared", "/private/tmp",
        _h("Library/LaunchAgents"), "/Library/LaunchAgents", "/Library/LaunchDaemons",
        "/usr/local/bin",
    ],
    "fim_ignore": [
        r"\.DS_Store$", r"\.localized$", r"/\._", r"\.swp$", r"~$", r"\.crdownload$", r"\.download/",
        r"\.part$", r"_history$", r"\.zsh_sessions", r"\.lesshst$", r"\.viminfo$", r"\.CFUserTextEncoding$",
        r"/\.Trash", r"\.zcompdump", r"/claude-\d+/", r"\.sb-[0-9a-f]+-", r"/\.cache/", r"\.lock$",
        r"/com\.apple\.launchd", r"\.sock$", r"/powerlog", r"\.claude",
    ],
    # Chemins jamais analysés par l'antimalware (regex) : données d'assistants IA, caches navigateurs,
    # dépôts de paquets… Ils contiennent du texte qui *parle* de malwares (règles, docs, conversations)
    # et ne sont pas exécutés tels quels : les analyser ne produit que des faux positifs.
    "scan_exclude": [
        r"/\.(claude|codex|cursor|gemini|copilot|continue|aider)(/|$)",
        r"/Library/Application Support/(Claude|Cursor|Code|ChatGPT)/",
        r"/Library/Caches/(Google/Chrome|com\.google\.Chrome|BraveSoftware|Microsoft Edge|Firefox|com\.apple\.Safari|com\.operasoftware|Arc|company\.thebrowser)",
        r"/Library/Application Support/(Google/Chrome|BraveSoftware|Microsoft Edge|Arc)/.*/(Cache|Code Cache|GPUCache|Service Worker|IndexedDB|File System)/",
        r"/Library/Application Support/Firefox/Profiles/.*/(cache2|storage)/",
        r"/Library/(Containers/com\.apple\.Safari|Safari)/",
        r"/node_modules/", r"/\.git/", r"/\.npm/", r"/\.cache/", r"/site-packages/", r"/\.venv/",
        r"/Library/Caches/(Homebrew|pip|pypoetry|yarn|com\.apple\.dt\.Xcode)/",
        r"/Library/Developer/(Xcode|CoreSimulator)/",
    ],
    "suspicious_ports":[4444, 4445, 1337, 31337, 6667, 6697, 3333, 5555, 7777, 8888, 9001, 9050, 14444, 45700, 1080],
    "ioc_ips": [],
    "ioc_hashes": [],
}
