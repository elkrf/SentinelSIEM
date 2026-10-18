# Changelog

Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/).

## [Non publié]

### Ajouté
- Détail d'une alerte : encadré « En gros » pour toutes les alertes — ce qui s'est passé concrètement
  (programme, fichier, service), ce que signifie ce type d'alerte, pourquoi elle s'est déclenchée
  (détail des corrélations), verdict probable et conseils. Calcul local (`backend/siem/explain.py`).
- Bouton « Analyse IA approfondie » : Claude (CLI `claude`, sans aucun outil) analyse l'alerte et les
  alertes voisines ; résultat mis en cache (table `alert_ai_notes`).

### Modifié — réduction des faux positifs
- Antimalware : nouveau paramètre `scan_exclude` (données d'assistants IA `~/.claude`, `~/.codex`…,
  caches navigateurs, `node_modules`, `.git`, caches de développement), aussi appliqué aux analyses à la demande.
- YARA : les règles « texte » (AMOS, reverse shell, dropper, mineur, ransomware, hacktool…) ne s'appliquent
  plus qu'à du contenu exécutable (Mach-O, shebang, AppleScript compilé, extension de script) ; une doc,
  un JSON ou un fichier de règles qui cite un malware ne déclenche plus rien.
- Mach-O dans un emplacement à risque : plus d'alerte pour un binaire correctement signé ; une seule alerte
  par application `.app` non signée.
- Anti-doublon : une même détection (hash + signature) n'est remontée qu'une fois par 24 h.
- Règles 100316 (recherche d'outils de sécurité) et 100330 (CPU) : moins de déclenchements sur les outils
  légitimes ; 100161 passe au niveau 3, la corrélation 100162 exige ≈ 5 tentatives ratées en 2 min.

## [1.0.0] — 2026-10-10

Première version.

### Ajouté
- Pipeline collecteurs → moteur de règles → SQLite → WebSocket / notifications macOS.
- Collecteurs : journaux unifiés macOS, FIM temps réel (FSEvents), processus, réseau, persistance,
  comptes & périphériques, SCA (26 contrôles CIS), antimalware.
- Antimalware : ClamAV (`clamd`) + 15 règles YARA macOS + heuristiques + IOC, quarantaine automatique.
- 136 règles de détection style Wazuh (niveaux 0–15, MITRE ATT&CK, corrélation fréquence/fenêtre).
- Console web : vue d'ensemble, événements, chasse aux menaces, matrice ATT&CK, malwares, FIM, SCA,
  processus, réseau, persistance, inventaire, règles, modules, paramètres.
- `siemctl` et `scripts/install.sh` (services launchd, application `SentinelSIEM.app`).
