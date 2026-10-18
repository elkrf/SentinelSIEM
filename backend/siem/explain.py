"""Explication en langage clair de chaque alerte : ce qui s'est passé, pourquoi la règle s'est
déclenchée, verdict probable et conseils. Calcul local, instantané, sans envoi de données."""
import os
import re
import time

from . import db
from .config import HOME

H = str(HOME)

# Processus macOS courants dans les journaux, décrits simplement
PROC_DESC = {
    "opendirectoryd": "le service macOS qui vérifie les mots de passe des comptes",
    "loginwindow": "l'écran de connexion / de déverrouillage de macOS",
    "authd": "le service macOS qui accorde les autorisations administrateur",
    "sudo": "la commande qui exécute une action en administrateur",
    "su": "la commande de changement d'utilisateur",
    "sshd": "le serveur SSH (connexion à distance en ligne de commande)",
    "screensharingd": "le service de partage d'écran (VNC)",
    "syspolicyd": "Gatekeeper, le contrôle des applications téléchargées",
    "XProtect": "XProtect, l'antivirus intégré à macOS",
    "socketfilterfw": "le pare-feu applicatif de macOS",
    "sysadminctl": "l'outil de gestion des comptes utilisateurs",
}

# Ce que signifie chaque famille d'alerte, « en gros »
GROUP_TEXT = [
    ("brute_force", "Plusieurs mots de passe refusés en peu de temps. Ça peut être quelqu'un qui essaie de deviner un mot de passe, mais le plus souvent c'est simplement une personne qui s'est trompée plusieurs fois, ou une application qui réessaie avec un ancien mot de passe."),
    ("authentication_failed", "Un mot de passe a été refusé. Une seule erreur de ce type est banale (faute de frappe)."),
    ("authentication_success", "Une connexion a réussi. C'est une information de traçabilité."),
    ("reverse_shell", "Un « reverse shell » donne à une machine distante le contrôle de la ligne de commande de ce Mac. C'est une technique typique de piratage."),
    ("stealer", "Un « infostealer » est un logiciel qui vole mots de passe, cookies, trousseau et portefeuilles crypto."),
    ("ransomware", "Comportement de rançongiciel : chiffrement ou modification massive de fichiers pour exiger une rançon."),
    ("cryptominer", "Un cryptomineur utilise le processeur à votre insu pour miner de la cryptomonnaie."),
    ("c2", "Connexion vers un serveur pouvant servir à piloter un logiciel malveillant (C2) ou à miner."),
    ("persistence", "Un élément a été configuré pour se lancer automatiquement (au démarrage ou à l'ouverture de session). Les installateurs légitimes le font, les malwares aussi pour survivre au redémarrage."),
    ("defense_evasion", "Une action qui affaiblit les protections de macOS (Gatekeeper, pare-feu, SIP, journaux…)."),
    ("credential_access", "Accès à des secrets : trousseau, mots de passe enregistrés, données de navigateur."),
    ("exfiltration", "Des données sont envoyées vers l'extérieur."),
    ("collection", "Collecte de données (captures d'écran, presse-papiers, archives) pouvant précéder un vol."),
    ("discovery", "Reconnaissance : un programme inventorie le système, les comptes ou les protections installées."),
    ("privilege", "Utilisation ou obtention de droits administrateur."),
    ("account", "Modification des comptes utilisateurs de ce Mac."),
    ("malware", "Un moteur antimalware a reconnu des motifs connus de logiciel malveillant."),
    ("xprotect", "Résultat remonté par XProtect, l'antivirus intégré d'Apple."),
    ("gatekeeper", "Gatekeeper a empêché l'ouverture d'une application non approuvée par Apple."),
    ("ssh", "Activité liée à SSH (accès à distance)."),
    ("vnc", "Activité liée au partage d'écran."),
    ("firewall", "Le pare-feu de macOS a changé d'état."),
    ("dns", "Le fichier /etc/hosts redirige des noms de domaine : il peut servir à bloquer des sites ou à détourner du trafic."),
    ("system_config", "Un fichier de configuration du système a changé."),
    ("software", "Changement dans les applications installées."),
    ("downloads", "Un nouveau fichier est arrivé dans un dossier surveillé."),
    ("malware_staging", "Un exécutable a été déposé là où les malwares s'installent souvent (dossiers temporaires ou partagés)."),
    ("suspicious_location", "Un programme tourne depuis un dossier temporaire ou partagé, ce que font rarement les applications normales."),
    ("download_execute", "Un script téléchargé est exécuté directement, sans être vérifié."),
    ("obfuscation", "Une commande est volontairement rendue illisible (encodée), technique courante pour cacher une action."),
    ("anonymizer", "Tor permet de naviguer anonymement ; légitime pour certains usages, utilisé aussi par des malwares."),
    ("resource", "Un programme utilise le processeur à fond depuis plusieurs minutes."),
    ("listening", "Un programme attend des connexions entrantes sur un port réseau."),
    ("usb", "Un périphérique a été branché."),
    ("hardware", "Un disque ou un volume a été connecté."),
    ("compliance", "Contrôle de configuration de sécurité (référentiel CIS) : un réglage recommandé n'est pas appliqué."),
    ("sca", "Évaluation de la configuration de sécurité du Mac."),
    ("active_response", "Sentinel a réagi automatiquement pour neutraliser une menace."),
    ("heuristic", "Détection par comportement suspect, pas par signature : plus de risques de fausse alerte."),
    ("ioc", "L'élément figure dans votre liste d'indicateurs de compromission (IOC)."),
    ("fim", "Le contrôle d'intégrité a vu un fichier surveillé changer."),
    ("siem", "Événement interne de SentinelSIEM."),
    ("update", "Mise à jour des signatures antivirus."),
]

ADVICE = [
    ("brute_force", ["Si c'est vous qui vous êtes trompé de mot de passe, cliquez sur « Faux positif ».",
                     "Sinon, vérifiez qu'aucune application ne demande en boucle un ancien mot de passe (Trousseau, Wi-Fi, comptes internet), et changez votre mot de passe en cas de doute."]),
    ("reverse_shell", ["Terminez le processus et coupez le réseau si vous n'êtes pas à l'origine de la commande.", "Cherchez comment il a été lancé (processus parent, éléments de persistance)."]),
    ("stealer", ["Ne saisissez aucun mot de passe dans une fenêtre inattendue.", "Si le fichier a été exécuté : changez vos mots de passe depuis un autre appareil et vérifiez vos portefeuilles crypto."]),
    ("ransomware", ["Débranchez les disques de sauvegarde et coupez le réseau immédiatement si ce n'est pas vous."]),
    ("persistence", ["Vérifiez que vous reconnaissez l'application qui a créé cet élément. Si oui, c'est normal ; sinon, regardez la page « Persistance »."]),
    ("malware", ["Si le fichier vient d'une source sûre et que l'emplacement est un dossier de développement ou de cache, c'est probablement une fausse alerte.",
                 "Sinon, ne l'ouvrez pas et laissez-le en quarantaine."]),
    ("defense_evasion", ["Si ce n'est pas vous qui avez fait ce changement, rétablissez la protection et cherchez quel programme l'a fait."]),
    ("compliance", ["Corrigez le réglage si c'est possible (voir la page SCA), ou ignorez-le si c'est un choix volontaire."]),
    ("listening", ["Si le port n'écoute que sur 127.0.0.1, il n'est pas accessible depuis le réseau."]),
]

BENIGN_PATH_HINTS = [
    (r"/\.(claude|codex|cursor|gemini|copilot)(/|$)", "données d'un assistant de code IA (conversations, historique), qui citent souvent du code de sécurité"),
    (r"/Library/Caches/|/Cache_Data/|/Code Cache/", "cache de navigateur ou d'application"),
    (r"/node_modules/|/site-packages/|/\.venv/|/\.git/", "dépendances de développement"),
    (r"/SentinelSIEM/", "fichiers de SentinelSIEM lui-même (règles, quarantaine)"),
    (r"^/(System|usr/(bin|sbin|libexec))/", "fichier du système macOS, protégé par Apple"),
]


def _short(s, n=160):
    s = re.sub(r"\s+", " ", str(s or "")).strip()
    return s if len(s) <= n else s[: n - 1] + "…"


def _home(p):
    return ("~" + p[len(H):]) if p and p.startswith(H) else p


def _hm(ts):
    return time.strftime("%H:%M:%S", time.localtime(ts))


def _size(n):
    try:
        n = float(n)
    except (TypeError, ValueError):
        return ""
    for u in ("octets", "Ko", "Mo", "Go"):
        if n < 1024 or u == "Go":
            return f"{n:.0f} {u}" if u == "octets" else f"{n:.1f} {u}"
        n /= 1024


def _what(a, d, rule):
    """Phrase concrète : qui, quoi, où."""
    m, t = a.get("module"), d.get("type")
    path = _home(d.get("path") or "")
    if m == "malware":
        if t in ("yara", "clamav", "ioc", "heuristic"):
            eng = {"yara": "Le moteur YARA", "clamav": "L'antivirus ClamAV", "ioc": "La liste d'IOC", "heuristic": "L'analyse heuristique"}[t]
            what = d.get("yara_description") or d.get("signature")
            fam = f" (famille {d['family']})" if d.get("family") and d.get("family") not in ("Test",) else ""
            s = f"{eng} a signalé le fichier « {d.get('filename') or os.path.basename(path)} » dans {os.path.dirname(path) or '?'} : {what}{fam}."
            if d.get("size"):
                s += f" Taille : {_size(d['size'])}."
            if d.get("reason") == "scan_manuel":
                s += " Trouvé pendant une analyse à la demande."
            if d.get("quarantine_id"):
                s += " Le fichier a été déplacé en quarantaine : il ne peut plus être ouvert ni exécuté."
            return s
        if t == "scan_done":
            return f"Une analyse antimalware de {_home(d.get('path'))} s'est terminée : {d.get('scanned')} fichiers vérifiés, {d.get('found')} détection(s)."
        if t == "update":
            return "Les signatures de l'antivirus ClamAV ont été mises à jour." if d.get("ok") else "La mise à jour des signatures ClamAV a échoué."
    if m == "active_response":
        if t == "quarantine":
            return f"Sentinel a automatiquement isolé le fichier {path} (détecté comme « {d.get('signature')} ») dans sa quarantaine."
        if t == "kill":
            return f"Le processus {d.get('name')} (PID {d.get('pid')}) a été arrêté par {d.get('by')}."
        if t == "restore":
            return f"Le fichier {path} a été sorti de quarantaine par {d.get('by')}."
    if m == "process":
        who = f"sous le compte {d['user']}" if d.get("user") else ""
        par = f", lancé par « {d['parent']} »" if d.get("parent") else ""
        if t == "high_cpu":
            return f"Le programme « {d.get('name')} » ({_home(d.get('exe')) or '?'}) a utilisé {d.get('cpu')} % du processeur pendant plus de {d.get('duration', 120)} secondes{par}."
        return f"Le programme « {d.get('name')} » ({_home(d.get('exe')) or '?'}{par}, {who}) a exécuté la commande : {_short(d.get('cmdline'), 220)}"
    if m == "network":
        if t == "listen_new":
            scope = "uniquement en local (127.0.0.1), donc invisible depuis le réseau" if str(d.get("local_host", "")).startswith(("127.", "[::1]", "::1", "localhost")) else "sur le réseau, donc joignable par d'autres machines"
            return f"Le programme « {d.get('process')} » (PID {d.get('pid')}) a ouvert le port {d.get('local_port')} et écoute {scope}."
        return f"Le programme « {d.get('process')} » (PID {d.get('pid')}) s'est connecté à {d.get('remote')}" + (" (adresse Internet publique)." if d.get("public") else ".")
    if m == "fim":
        verb = {"added": "créé", "modified": "modifié", "deleted": "supprimé"}.get(t)
        if t == "baseline":
            return f"Le contrôle d'intégrité a indexé {d.get('count')} fichiers de référence."
        if verb and str(d.get("path", "")).endswith(".app") and os.path.dirname(d["path"]) == "/Applications":
            return f"L'application « {d.get('filename') or os.path.basename(d['path'])} » a été " + ("installée" if t == "added" else "supprimée" if t == "deleted" else "mise à jour") + " dans le dossier Applications."
        if verb:
            s = f"Le fichier {path} a été {verb}."
            if d.get("changes"):
                s += f" Changements : {d['changes']}."
            if d.get("owner") and t != "deleted":
                s += f" Propriétaire : {d['owner']}."
            return s
    if m == "persistence":
        verb = {"new": "est apparu", "modified": "a été modifié", "removed": "a été supprimé", "existing": "est présent"}.get(t, "")
        s = f"L'élément de démarrage automatique « {d.get('label')} » ({d.get('kind')}) {verb}"
        if d.get("program"):
            s += f". Il lance : {_home(_short(d.get('program'), 160))}"
        if d.get("path") and d.get("path") != "crontab":
            s += f" (fichier {_home(d['path'])})"
        if d.get("signer"):
            s += f". Signature : {d['signer']}"
        return s + "."
    if m == "logs":
        p = d.get("process") or ""
        desc = PROC_DESC.get(p) or next((v for k, v in PROC_DESC.items() if p.startswith(k)), "")
        return f"Le journal système de macOS rapporte que « {p} »" + (f" ({desc})" if desc else "") + f" a écrit : {_short(d.get('message'), 200)}"
    if m == "system":
        return {
            "user_created": f"Un nouveau compte « {d.get('user')} » a été créé sur ce Mac.",
            "user_deleted": f"Le compte « {d.get('user')} » a été supprimé.",
            "admin_added": f"« {d.get('user')} » a reçu les droits administrateur.",
            "admin_removed": f"« {d.get('user')} » a perdu les droits administrateur.",
            "usb_connected": f"Le périphérique USB « {d.get('name')} » ({d.get('vendor')}) a été branché.",
            "volume_mounted": f"Le volume « {d.get('name')} » a été monté.",
        }.get(t, "")
    if m == "sca":
        if t == "summary":
            return f"L'évaluation de sécurité de la configuration donne {d.get('score')} % ({d.get('passed')} contrôles conformes, {d.get('failed')} non conformes)."
        return f"Contrôle « {d.get('title')} » ({d.get('cis')}) : " + {"failed": "non conforme.", "regression": "était conforme et ne l'est plus.", "fixed": "désormais conforme."}.get(t, "")
    if m == "siem":
        return {"start": "SentinelSIEM vient de démarrer.", "auth_success": f"Connexion réussie à la console par « {d.get('user')} ».",
                "auth_failed": f"Mot de passe refusé à la console pour « {d.get('user')} ».",
                "settings": f"Les paramètres ont été modifiés par {d.get('user')} ({', '.join(d.get('keys') or [])})."}.get(t, "")
    return a.get("description", "")


def _correlation(a, d, rule):
    """Pour une règle de fréquence : combien d'évènements, sur quelle durée."""
    if not rule or rule.if_matched_sid is None:
        return None
    sid = int(rule.if_matched_sid)
    rows = db.query("SELECT ts FROM alerts WHERE rule_id=? AND ts BETWEEN ? AND ? ORDER BY ts",
                    (sid, a["ts"] - rule.timeframe - 1, a["ts"] + 1))
    freq = d.get("correlated_count") or rule.frequency
    n = len(rows) or freq
    s = f"Cette alerte est une corrélation : elle s'est déclenchée parce que la règle {sid} s'est produite au moins {freq} fois en {rule.timeframe} secondes."
    if rows:
        s += f" Ici, {n} occurrence(s) entre {_hm(rows[0]['ts'])} et {_hm(rows[-1]['ts'])}."
    day = db.query_one("SELECT count(*) c FROM alerts WHERE rule_id=? AND ts BETWEEN ? AND ?", (sid, a["ts"] - 86400, a["ts"]))
    if day and day["c"]:
        s += f" Sur les dernières 24 h : {day['c']} occurrence(s) de la règle {sid}."
    return s


def _verdict(a, d, rule):
    lvl, m, t = a.get("level", 0), a.get("module"), d.get("type")
    groups = set((a.get("groups") or "").split(","))
    path = d.get("path") or d.get("exe") or ""
    sig = str(d.get("signature") or "")

    if m in ("siem", "sca") and t in ("start", "auth_success", "settings", "summary", "fixed") or t in ("baseline", "scan_done", "update"):
        return "info", "Information", "Évènement normal de fonctionnement, rien à faire."
    if "eicar" in sig.lower() or d.get("family") == "Test":
        return "ok", "Test", "C'est le fichier de test antivirus standard EICAR, inoffensif par conception."
    for rx, why in BENIGN_PATH_HINTS:
        if path and re.search(rx, path):
            if m in ("malware", "active_response"):
                return "ok", "Faux positif probable", f"L'emplacement correspond à des {why}. Ces fichiers contiennent du texte qui ressemble à du code malveillant sans en être."
            return "ok", "Bénin probable", f"L'emplacement correspond à des {why}."
    if d.get("signature") == "macho_in_risky_dir":
        return "ok", "Bénin probable", "Le programme est correctement signé par son éditeur ; seul son emplacement (Téléchargements) a déclenché l'alerte."
    parent = str(d.get("parent") or "")
    if m == "process" and (re.match(r"^(claude|codex|cursor|Cursor|node)$", parent) and re.search(r"/\.(claude|codex)/", str(d.get("cmdline", ""))) or "SentinelSIEM" in str(d.get("cmdline", ""))):
        return "ok", "Bénin probable", f"La commande a été lancée par un assistant de code IA (« {parent} ») ou par l'administration de SentinelSIEM, à votre demande."
    msg = str(d.get("message") or "")
    if "XProtect" in str(d.get("process", "")) and "NoThreatDetected" in msg and re.search(r'"caused_by"\s*:\s*\[\s*\]', msg):
        return "ok", "Faux positif", "XProtect indique explicitement « NoThreatDetected » (aucune menace) : c'est un compte rendu d'analyse normal."
    signer = str(d.get("signer") or "")
    if m == "persistence" and "Developer ID" in signer and str(d.get("program", "")).startswith("/Applications/"):
        who = re.sub(r"^.*Developer ID Application:\s*", "", signer)
        return "ok", "Bénin probable", f"Le programme lancé est une application installée, signée par {who}. C'est typique d'un logiciel qui s'installe normalement."
    if m == "network" and t == "listen_new" and str(d.get("local_host", "")).startswith(("127.", "[::1]", "::1")):
        return "ok", "Bénin probable", "Le port n'est accessible que depuis ce Mac."
    if m == "process" and t == "high_cpu":
        return "warn", "À vérifier", "Un usage CPU élevé est souvent normal (compilation, export vidéo, analyse antivirus). Suspect seulement si vous ne reconnaissez pas le programme."
    if "brute_force" in groups and m in ("logs", None, "") and "src_ip" not in d:
        return "warn", "À vérifier", "Les tentatives sont locales (personne ne s'est connecté à distance). Si c'est vous qui vous êtes trompé de mot de passe, c'est une fausse alerte."
    if m == "persistence" and "Apple" in str(d.get("signer", "")):
        return "ok", "Bénin probable", "Le programme lancé est signé par Apple."
    if m == "active_response" and t == "quarantine":
        return "warn", "Neutralisé", "La menace éventuelle est isolée. Vérifiez l'alerte de détection associée pour savoir si c'était justifié."
    if t == "heuristic":
        return "warn", "À vérifier", "Détection par comportement, sans signature de malware connue."
    if lvl >= 12:
        return "crit", "Suspect", "Niveau de gravité élevé : à traiter en priorité si vous n'êtes pas à l'origine de cette action."
    if lvl >= 7:
        return "warn", "À vérifier", "Action inhabituelle mais souvent légitime : vérifiez que vous la reconnaissez."
    return "info", "Information", "Évènement de faible gravité, conservé pour la traçabilité."


def explain(a: dict, d: dict, rule=None) -> dict:
    groups = [g for g in (a.get("groups") or "").split(",") if g]
    meaning = next((txt for g, txt in GROUP_TEXT if g in groups), "")
    what = _what(a, d, rule) or a.get("description", "")
    why = []
    corr = _correlation(a, d, rule)
    if corr:
        why.append(corr)
    if d.get("module") == "malware" and d.get("type") == "yara":
        why.append(f"Règle YARA « {d.get('signature')} » : elle cherche des chaînes caractéristiques dans le contenu du fichier.")
    level, label, reason = _verdict(a, d, rule)
    advice = next((adv for g, adv in ADVICE if g in groups), [])
    if level in ("ok", "info") and not advice:
        advice = ["Rien à faire. Vous pouvez marquer l'alerte comme « Résolue » ou « Faux positif »."]
    return {"summary": what, "meaning": meaning, "why": why,
            "verdict": {"level": level, "label": label, "reason": reason}, "advice": advice}
