# Changelog

Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/).

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
