"""Security Configuration Assessment : audit de durcissement macOS inspiré du CIS Benchmark."""
import json
import os
import socket
import stat
import subprocess
import threading
import time

from .. import db
from ..config import HOME
from .base import Collector


def sh(args, timeout=30):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return (r.stdout + r.stderr).strip()
    except Exception as e:
        return f"ERREUR: {e}"


def defaults_read(domain, key):
    out = sh(["/usr/bin/defaults", "read", domain, key])
    return None if "does not exist" in out else out.strip()


def port_open(port):
    s = socket.socket()
    s.settimeout(0.5)
    try:
        return s.connect_ex(("127.0.0.1", port)) == 0
    finally:
        s.close()


# (id, titre, catégorie, sévérité, réf CIS, fonction -> (pass|fail|na, détail), remédiation)
def _filevault():
    o = sh(["/usr/bin/fdesetup", "status"])
    return ("pass" if "On" in o else "fail"), o


def _firewall():
    o = sh(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
    return ("pass" if "enabled" in o.lower() and "disabled" not in o.lower() else "fail"), o


def _stealth():
    o = sh(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getstealthmode"])
    return ("pass" if "enabled" in o.lower() or " on" in o.lower() else "fail"), o


def _sip():
    o = sh(["/usr/bin/csrutil", "status"])
    return ("pass" if "enabled" in o.lower() else "fail"), o


def _gatekeeper():
    o = sh(["/usr/sbin/spctl", "--status"])
    return ("pass" if "assessments enabled" in o else "fail"), o


def _su_pref(key):
    def f():
        v = defaults_read("/Library/Preferences/com.apple.SoftwareUpdate", key)
        if v is None:
            return "pass", f"{key} non défini (valeur par défaut macOS : activé)"
        return ("pass" if v == "1" else "fail"), f"{key} = {v}"
    return f


def _ssh():
    return ("fail" if port_open(22) else "pass"), "Port 22 ouvert (Session à distance activée)" if port_open(22) else "SSH désactivé"


def _screen_sharing():
    o = port_open(5900)
    return ("fail" if o else "pass"), "Port 5900 (VNC) ouvert" if o else "Partage d'écran désactivé"


def _smb():
    o = port_open(445)
    return ("fail" if o else "pass"), "Port 445 (SMB) ouvert" if o else "Partage de fichiers désactivé"


def _remote_events():
    o = port_open(3031)
    return ("fail" if o else "pass"), "Port 3031 ouvert" if o else "Événements Apple distants désactivés"


def _guest():
    v = defaults_read("/Library/Preferences/com.apple.loginwindow", "GuestEnabled")
    return ("fail" if v == "1" else "pass"), f"GuestEnabled = {v}"


def _autologin():
    v = defaults_read("/Library/Preferences/com.apple.loginwindow", "autoLoginUser")
    return ("fail" if v else "pass"), f"autoLoginUser = {v}" if v else "Connexion automatique désactivée"


def _pw_hints():
    v = defaults_read("/Library/Preferences/com.apple.loginwindow", "RetriesUntilHint")
    return ("pass" if v in (None, "0") else "fail"), f"RetriesUntilHint = {v}"


def _screen_lock():
    o = sh(["/usr/sbin/sysadminctl", "-screenLock", "status"])
    o = o.split("] ", 1)[-1].strip()
    if "immediate" in o or "delay is 0" in o:
        return "pass", o
    if "off" in o.lower():
        return "fail", o
    try:
        secs = int(o.split("delay is")[-1].split()[0])
        return ("pass" if secs <= 5 else "fail"), o
    except Exception:
        return "na", o


def _show_ext():
    v = defaults_read("NSGlobalDomain", "AppleShowAllExtensions")
    return ("pass" if v == "1" else "fail"), f"AppleShowAllExtensions = {v}"


def _home_perms():
    m = stat.S_IMODE(os.stat(HOME).st_mode)
    return ("pass" if not (m & 0o007) else "fail"), f"{HOME} : {oct(m)}"


def _ssh_perms():
    p = HOME / ".ssh"
    if not p.exists():
        return "na", "Pas de répertoire ~/.ssh"
    m = stat.S_IMODE(os.stat(p).st_mode)
    bad = [f.name for f in p.iterdir() if f.is_file() and f.name.startswith("id_") and not f.name.endswith(".pub") and stat.S_IMODE(f.stat().st_mode) & 0o077]
    if m & 0o077 or bad:
        return "fail", f"~/.ssh {oct(m)}; clés trop permissives : {', '.join(bad) or '-'}"
    return "pass", f"~/.ssh {oct(m)}"


def _root():
    o = sh(["/usr/bin/dscl", ".", "-read", "/Users/root", "AuthenticationAuthority"])
    enabled = "ShadowHash" in o
    return ("fail" if enabled else "pass"), "Compte root activé" if enabled else "Compte root désactivé"


def _xprotect():
    p = "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"
    v = sh(["/usr/bin/defaults", "read", p.replace(".plist", ""), "CFBundleShortVersionString"])
    if "does not exist" in v or "ERREUR" in v:
        return "fail", "XProtect introuvable"
    return "pass", f"XProtect version {v}"


def _airdrop():
    v = defaults_read("com.apple.NetworkBrowser", "DisableAirDrop")
    return ("pass" if v == "1" else "fail"), f"DisableAirDrop = {v}"


def _secure_kb():
    v = defaults_read("com.apple.Terminal", "SecureKeyboardEntry")
    return ("pass" if v == "1" else "fail"), f"Terminal SecureKeyboardEntry = {v}"


def _sudo_timeout():
    o = sh(["/bin/cat", "/etc/sudoers.d/timestamp"])
    return ("na", "Non vérifiable sans privilèges root") if "Permission" in o or "No such" in o else ("pass", o)


def _clamav():
    sock = "/opt/homebrew/var/run/clamav/clamd.sock"
    return ("pass" if os.path.exists(sock) else "fail"), "Démon ClamAV actif" if os.path.exists(sock) else "clamd non démarré"


def _sw_updates():
    o = sh(["/usr/sbin/softwareupdate", "-l"], timeout=180)
    if "No new software available" in o:
        return "pass", "Système à jour"
    items = [l.strip() for l in o.splitlines() if l.strip().startswith("* Label:") or l.strip().startswith("Title:")]
    return ("fail" if items else "na"), "\n".join(items[:10]) or o[-400:]


def _brew_outdated():
    try:
        o = subprocess.run(["/opt/homebrew/bin/brew", "outdated", "--json=v2"], capture_output=True, text=True, timeout=180,
                           env={**os.environ, "HOMEBREW_NO_AUTO_UPDATE": "1", "HOMEBREW_NO_ENV_HINTS": "1"}).stdout
    except Exception as e:
        return "na", str(e)
    try:
        d = json.loads(o)
        pk = [f"{x['name']} {x['installed_versions'][0]} → {x['current_version']}" for x in d.get("formulae", [])]
        pk += [f"{x['name']} → {x['current_version']}" for x in d.get("casks", [])]
        return ("pass" if not pk else "fail"), ("\n".join(pk[:30]) if pk else "Tous les paquets Homebrew sont à jour")
    except Exception:
        return "na", o[-300:]


CHECKS = [
    ("mac-1.1", "FileVault (chiffrement du disque) activé", "Chiffrement", "high", "CIS 2.5.1.1", _filevault,
     "Réglages Système → Confidentialité et sécurité → FileVault → Activer."),
    ("mac-1.2", "Pare-feu applicatif activé", "Réseau", "high", "CIS 2.2.1", _firewall,
     "Réglages Système → Réseau → Coupe-feu → Activer. ou: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on"),
    ("mac-1.3", "Mode furtif du pare-feu activé", "Réseau", "medium", "CIS 2.2.2", _stealth,
     "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on"),
    ("mac-1.4", "System Integrity Protection (SIP) activé", "Intégrité système", "critical", "CIS 5.1.2", _sip,
     "Redémarrer en mode récupération et exécuter : csrutil enable"),
    ("mac-1.5", "Gatekeeper activé", "Intégrité système", "high", "CIS 2.5.2.1", _gatekeeper,
     "sudo spctl --master-enable"),
    ("mac-1.6", "XProtect (antimalware Apple) présent", "Antimalware", "high", "CIS 5.x", _xprotect,
     "Mettre à jour macOS et activer « Installer les fichiers de données système et mises à jour de sécurité »."),
    ("mac-1.7", "Démon antivirus ClamAV actif", "Antimalware", "medium", "-", _clamav,
     "~/SentinelSIEM/siemctl start"),
    ("mac-2.1", "Recherche automatique des mises à jour", "Mises à jour", "high", "CIS 1.2", _su_pref("AutomaticCheckEnabled"),
     "Réglages Système → Général → Mise à jour de logiciels → Mises à jour automatiques."),
    ("mac-2.2", "Téléchargement automatique des mises à jour", "Mises à jour", "medium", "CIS 1.3", _su_pref("AutomaticDownload"),
     "Activer « Télécharger les nouvelles mises à jour lorsqu'elles sont disponibles »."),
    ("mac-2.3", "Installation auto. des réponses de sécurité", "Mises à jour", "high", "CIS 1.5", _su_pref("CriticalUpdateInstall"),
     "Activer « Installer les réponses de sécurité et les fichiers système »."),
    ("mac-2.4", "Aucune mise à jour macOS en attente", "Mises à jour", "high", "CIS 1.1", _sw_updates,
     "Réglages Système → Général → Mise à jour de logiciels."),
    ("mac-2.5", "Paquets Homebrew à jour", "Mises à jour", "medium", "-", _brew_outdated, "brew upgrade"),
    ("mac-3.1", "Session à distance (SSH) désactivée", "Partage", "high", "CIS 2.3.3.5", _ssh,
     "Réglages Système → Général → Partage → Session à distance → Désactiver."),
    ("mac-3.2", "Partage d'écran désactivé", "Partage", "high", "CIS 2.3.3.2", _screen_sharing,
     "Réglages Système → Général → Partage → Partage d'écran → Désactiver."),
    ("mac-3.3", "Partage de fichiers (SMB) désactivé", "Partage", "medium", "CIS 2.3.3.3", _smb,
     "Réglages Système → Général → Partage → Partage de fichiers → Désactiver."),
    ("mac-3.4", "Événements Apple distants désactivés", "Partage", "medium", "CIS 2.3.3.8", _remote_events,
     "Réglages Système → Général → Partage → Événements Apple distants → Désactiver."),
    ("mac-3.5", "AirDrop désactivé", "Partage", "low", "CIS 2.3.1.1", _airdrop,
     "defaults write com.apple.NetworkBrowser DisableAirDrop -bool true"),
    ("mac-4.1", "Compte invité désactivé", "Comptes", "high", "CIS 2.13.1", _guest,
     "Réglages Système → Utilisateurs et groupes → Utilisateur invité → Désactiver."),
    ("mac-4.2", "Connexion automatique désactivée", "Comptes", "high", "CIS 2.13.3", _autologin,
     "Réglages Système → Utilisateurs et groupes → Ouvrir automatiquement la session → Désactivé."),
    ("mac-4.3", "Indices de mot de passe désactivés", "Comptes", "medium", "CIS 2.11.4", _pw_hints,
     "sudo defaults write /Library/Preferences/com.apple.loginwindow RetriesUntilHint -int 0"),
    ("mac-4.4", "Compte root désactivé", "Comptes", "high", "CIS 5.6", _root,
     "dsenableroot -d"),
    ("mac-4.5", "Verrouillage d'écran immédiat", "Comptes", "high", "CIS 2.10.2", _screen_lock,
     "Réglages Système → Écran de verrouillage → Exiger le mot de passe : Immédiatement."),
    ("mac-5.1", "Répertoire personnel non lisible par tous", "Fichiers", "medium", "CIS 5.1.1", _home_perms,
     "chmod og-rwx ~"),
    ("mac-5.2", "Permissions SSH sûres", "Fichiers", "high", "-", _ssh_perms,
     "chmod 700 ~/.ssh && chmod 600 ~/.ssh/id_*"),
    ("mac-5.3", "Afficher toutes les extensions de fichiers", "Fichiers", "low", "CIS 6.1.1", _show_ext,
     "defaults write NSGlobalDomain AppleShowAllExtensions -bool true"),
    ("mac-5.4", "Saisie clavier sécurisée dans Terminal", "Fichiers", "low", "CIS 6.4.1", _secure_kb,
     "Terminal → menu Terminal → Saisie clavier sécurisée."),
]


class SCACollector(Collector):
    name = "sca"
    title = "Évaluation de la configuration (SCA)"
    description = "Audit de durcissement macOS (CIS Benchmark) : FileVault, pare-feu, SIP, Gatekeeper, partages, mises à jour…"
    interval = 1800

    def __init__(self):
        super().__init__()
        self.running = False
        self.lock = threading.Lock()

    def run_checks(self):
        if not self.lock.acquire(blocking=False):
            return
        self.running = True
        try:
            prev = {r["check_id"]: r["status"] for r in db.query("SELECT check_id, status FROM sca_results")}
            for cid, title, cat, sev, cis, fn, rem in CHECKS:
                try:
                    status, detail = fn()
                except Exception as e:
                    status, detail = "na", f"Erreur : {e}"
                db.execute(
                    "INSERT OR REPLACE INTO sca_results(check_id, title, category, status, detail, remediation, cis, severity, ts) VALUES(?,?,?,?,?,?,?,?,?)",
                    (cid, title, cat, status, detail, rem, cis, sev, time.time()),
                )
                old = prev.get(cid)
                ev = {"module": "sca", "check_id": cid, "title": title, "category": cat, "severity": sev,
                      "status": status, "detail": detail, "cis": cis, "remediation": rem}
                if status == "fail" and old != "fail":
                    ev["type"] = "regression" if old == "pass" else "failed"
                    self.emit(ev)
                elif status == "pass" and old == "fail":
                    self.emit({**ev, "type": "fixed"})
            self.emit({"module": "sca", "type": "summary", **score()})
        finally:
            self.running = False
            self.last_run = time.time()
            self.lock.release()

    def setup(self):
        time.sleep(90)  # laisser clamd et les autres services démarrer avant la première évaluation

    def tick(self):
        self.run_checks()


def score():
    rows = db.query("SELECT status FROM sca_results")
    p = sum(1 for r in rows if r["status"] == "pass")
    f = sum(1 for r in rows if r["status"] == "fail")
    n = sum(1 for r in rows if r["status"] == "na")
    return {"passed": p, "failed": f, "not_applicable": n, "score": round(100 * p / (p + f)) if p + f else 0}
