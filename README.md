<div align="center">

# 🛡️ SentinelSIEM

**SIEM / EDR local pour macOS — détection, antimalware, intégrité des fichiers et conformité, dans une console web inspirée de Wazuh.**

![Plateforme](https://img.shields.io/badge/plateforme-macOS%20Apple%20Silicon-black?logo=apple)
![Python](https://img.shields.io/badge/python-3.12-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-backend-009688?logo=fastapi&logoColor=white)
![ClamAV](https://img.shields.io/badge/antivirus-ClamAV%20%2B%20YARA-red)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-orange)
![Licence](https://img.shields.io/badge/licence-propri%C3%A9taire-lightgrey)

</div>

---

## Sommaire

- [Présentation](#présentation)
- [Fonctionnalités](#fonctionnalités)
- [Prérequis](#prérequis)
- [Installation](#installation)
- [Premier lancement](#premier-lancement)
- [Utilisation — `siemctl`](#utilisation--siemctl)
- [Console web](#console-web)
- [Personnalisation](#personnalisation)
- [Accès complet au disque](#accès-complet-au-disque-recommandé)
- [Architecture](#architecture)
- [Sécurité et données](#sécurité-et-données)
- [Dépannage](#dépannage)
- [Désinstallation](#désinstallation)
- [Limites connues](#limites-connues)

---

## Présentation

SentinelSIEM tourne **entièrement en local** sur le Mac : aucun serveur distant, aucune télémétrie.
Des collecteurs surveillent en continu les journaux système, les fichiers sensibles, les processus,
le réseau et la persistance ; un moteur de règles (style Wazuh) produit des alertes de niveau 0–15
mappées sur **MITRE ATT&CK**, stockées dans SQLite et poussées en temps réel dans la console web.

| | |
|---|---|
| **Console** | http://localhost:5601 (écoute uniquement sur `127.0.0.1`) |
| **Services** | 2 agents `launchd` lancés à l'ouverture de session (SIEM + démon ClamAV) |
| **Détection** | 136 règles · 15 règles YARA · 3,6 M+ signatures ClamAV · 26 contrôles SCA |
| **Lanceur** | `~/Applications/SentinelSIEM.app` |

## Fonctionnalités

| Module | Détection |
|---|---|
| **Journaux macOS** | Flux `log stream` : sudo (commandes, mots de passe erronés, refus), SSH (échecs, succès, force brute), partage d'écran, XProtect, blocages Gatekeeper, échecs de déverrouillage, pare-feu désactivé |
| **Intégrité des fichiers (FIM)** | SHA-256, permissions et propriétaire sur LaunchAgents/Daemons, `/etc`, `~/.ssh`, fichiers de démarrage du shell, Téléchargements, Bureau, `/Applications`, `/Users/Shared`, `/tmp`. Temps réel (FSEvents) + détection des changements survenus pendant l'arrêt. Corrélation suppression/chiffrement de masse (rançongiciel) |
| **Antimalware** | ClamAV (démon `clamd`, mises à jour toutes les 12 h) + 15 règles YARA macOS (AMOS/Atomic Stealer, voleurs de portefeuilles, reverse shells, droppers, rançongiciels, mineurs, webshells, keyloggers…) + heuristiques (Mach-O non signé, double extension, exécutables cachés) + IOC de hashs. **Quarantaine automatique** |
| **Processus** | Reverse shells, `curl … \| sh`, base64 obfusqué, fausses invites AppleScript, accès au trousseau et aux cookies/mots de passe des navigateurs, désactivation SIP/Gatekeeper/pare-feu, effacement des journaux, création de comptes, cryptomineurs (signatures + CPU soutenu), Tor, exécution depuis `/tmp`… |
| **Réseau** | Nouveaux ports en écoute, connexions vers ports C2/minage, IP malveillantes (IOC), interpréteurs connectés à Internet |
| **Persistance** | Inventaire et différentiel des LaunchAgents/Daemons, crontab, scripts shell ; signature du binaire lancé |
| **Comptes & périphériques** | Création/suppression de comptes, ajout au groupe admin, clés USB, volumes montés |
| **SCA (conformité)** | 26 contrôles inspirés du CIS Benchmark macOS (FileVault, pare-feu, SIP, Gatekeeper, XProtect, mises à jour, partages, compte invité, verrouillage d'écran…) avec remédiation ; alerte en cas de régression |

Chaque alerte reçoit un niveau **0–15**, un mapping **MITRE ATT&CK**, et déclenche une
**notification macOS** à partir du niveau 10 (seuil réglable).

---

## Prérequis

| Élément | Version | Rôle |
|---|---|---|
| **Mac Apple Silicon** (M1 et +) | `arm64` | Les chemins Homebrew `/opt/homebrew` sont codés en dur |
| **macOS** | récent (développé et testé sur macOS 27) | `log stream`, FSEvents, launchd |
| **Command Line Tools Xcode** | — | `git`, `osacompile`, `iconutil` |
| **Homebrew** | récent | Installe les dépendances système |
| **Python** | 3.12 (Homebrew) | Backend FastAPI — *installé automatiquement* |
| **ClamAV** | ≥ 1.4 (Homebrew) | Moteur antivirus `clamd` / `freshclam` — *installé automatiquement* |
| **YARA** | ≥ 4.5 (Homebrew) | Moteur YARA — *installé automatiquement* |
| **Espace disque** | ~1 Go | Signatures ClamAV + environnement Python |
| **Internet** | à l'installation | Téléchargement des signatures, puis mises à jour |

Seuls les deux premiers outils sont à installer à la main :

```bash
# 1. Command Line Tools Xcode
xcode-select --install

# 2. Homebrew (si absent)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

Dépendances Python (installées dans `.venv/` depuis [`requirements.txt`](requirements.txt)) :
`fastapi`, `uvicorn[standard]`, `psutil`, `watchdog`, `yara-python`, `pyyaml`.

---

## Installation

```bash
git clone https://github.com/ELKEMITE/SentinelSIEM.git ~/SentinelSIEM
cd ~/SentinelSIEM
./scripts/install.sh
```

Le script est **idempotent** (relançable sans risque) et :

1. installe `python@3.12`, `clamav` et `yara` via Homebrew (si absents) ;
2. configure ClamAV (`freshclam.conf`, `clamd.conf`) et télécharge les signatures ;
3. crée l'environnement virtuel `.venv/` et installe les dépendances Python ;
4. crée les services `launchd` `com.sentinelsiem.agent` et `com.sentinelsiem.clamd` ;
5. génère l'application `~/Applications/SentinelSIEM.app` (avec icône) ;
6. démarre les services et affiche les identifiants admin.

> ⏱️ La première installation prend quelques minutes (téléchargement des signatures ClamAV).

## Premier lancement

Les identifiants admin s'affichent en fin d'installation. Pour les retrouver :

```bash
./siemctl password
```

Puis ouvrir la console :

```bash
./siemctl open        # ou double-clic sur ~/Applications/SentinelSIEM.app
```

Se connecter avec l'utilisateur `admin`, puis **changer le mot de passe depuis la console**
(le fichier `data/admin_password.txt` est alors supprimé).

---

## Utilisation — `siemctl`

| Commande | Action |
|---|---|
| `siemctl status` | État des services, de la console et de ClamAV |
| `siemctl start` / `stop` / `restart` | Démarrer, arrêter, redémarrer le SIEM et l'antivirus |
| `siemctl open` | Ouvrir la console (démarre les services si besoin) |
| `siemctl logs` | Suivre les journaux du SIEM en direct |
| `siemctl password` | Afficher le mot de passe admin initial |
| `siemctl reset-password` | Générer un nouveau mot de passe admin |
| `siemctl update-signatures` | Mettre à jour les signatures ClamAV immédiatement |
| `siemctl uninstall` | Retirer services et application (données conservées) |

Astuce : `ln -s ~/SentinelSIEM/siemctl /opt/homebrew/bin/siemctl` pour l'appeler de n'importe où.

> Le port d'écoute (`5601`) et l'adresse (`127.0.0.1`) sont définis dans le service launchd généré
> par `scripts/install.sh`. **Ne pas exposer la console sur le réseau** : elle permet notamment
> d'arrêter des processus.

---

## Console web

**Vue d'ensemble** · **Événements de sécurité** (détail, statut, export CSV/JSON) · **Chasse aux menaces**
(langage de requête + histogramme) · **Matrice MITRE ATT&CK** · **Malwares** (analyse à la demande,
quarantaine, test EICAR) · **FIM** · **SCA** · **Processus** (avec arrêt de processus) · **Réseau** ·
**Persistance** · **Inventaire** · **Règles** · **Modules** · **Paramètres** (IOC, chemins surveillés,
quarantaine auto…). Alertes en temps réel par **WebSocket**.

### Langage de chasse

```
level>=12                       module:process mitre:T1059
group:authentication_failed     tactic:Persistence status:new
path:Downloads                  user:root "reverse"
```

---

## Personnalisation

| Quoi | Où | Prise en compte |
|---|---|---|
| **Règles** | `rules/9000-local_rules.yml` — même `id` = remplace une règle ; `enabled: false` = désactive | *Règles → Recharger* |
| **YARA** | Déposer des fichiers `.yar` dans `yara/` | *Règles → Recharger* |
| **IOC** | *Paramètres → Indicateurs de compromission* (IP, hashs SHA-256, ports) | immédiate |
| **Chemins FIM / analyse** | *Paramètres* (valeurs par défaut dans `backend/siem/config.py`) | immédiate |

Exemple de règle locale :

```yaml
- id: 900001
  level: 12
  module: process
  type: [new]
  match: {cmdline: 'ma-commande-suspecte'}
  description: 'Commande interdite : {name} (PID {pid})'
  mitre: [T1059]
  groups: [process, local]
```

---

## Accès complet au disque (recommandé)

macOS protège Bureau, Documents et certains dossiers. Pour que le FIM et l'antivirus voient tout :

1. *Réglages Système → Confidentialité et sécurité → Accès complet au disque → +*
2. ⌘⇧G puis coller :
   `/opt/homebrew/opt/python@3.12/Frameworks/Python.framework/Versions/3.12/Resources/Python.app`
3. `siemctl restart`

Les avertissements de permission éventuels apparaissent dans *Modules & agent*.

---

## Architecture

```
SentinelSIEM/
├── backend/siem/
│   ├── app.py            API REST FastAPI + WebSocket + service de la console
│   ├── bus.py            pipeline : collecteurs → moteur de règles → SQLite → WebSocket / notifications
│   ├── rules.py          moteur de règles (regex, niveaux, corrélation fréquence/fenêtre)
│   ├── mitre.py          référentiel MITRE ATT&CK
│   ├── auth.py           authentification (PBKDF2-SHA256 + sessions)
│   ├── db.py · config.py · inventory.py
│   └── collectors/       unifiedlog · fim · process · network · malware · persistence · system · sca
├── rules/*.yml           règles de détection (style Wazuh, MITRE ATT&CK)
├── yara/*.yar            règles YARA macOS
├── frontend/             console web (HTML / CSS / JS, Chart.js)
├── scripts/install.sh    installation idempotente
├── siemctl               contrôle des services
└── data/                 (généré, non versionné) siem.db · quarantine/ · logs/ · admin_password.txt
```

```
 log stream ──┐
 FSEvents    ─┤                 ┌────────────┐     ┌────────┐     ┌────────────┐
 psutil      ─┼─► collecteurs ─►│  moteur de │────►│ SQLite │────►│ API + WS   │──► console web
 ClamAV/YARA ─┤                 │  règles    │     └────────┘     └────────────┘
 SCA         ─┘                 └─────┬──────┘
                                      └──► notifications macOS (niveau ≥ 10) · quarantaine
```

---

## Sécurité et données

- **100 % local** : la console n'écoute que sur `127.0.0.1`.
- Le dossier **`data/` n'est jamais versionné** (`.gitignore`) : il contient la base d'alertes,
  les journaux, le mot de passe initial et la **quarantaine (fichiers malveillants neutralisés)**.
- Mots de passe stockés en PBKDF2-SHA256 (310 000 itérations, sel aléatoire) ; sessions de 12 h.
- Rétention des événements : 30 jours par défaut (*Paramètres*).

## Dépannage

| Symptôme | Solution |
|---|---|
| Console injoignable | `siemctl status`, puis `siemctl logs` ; vérifier que le port est libre : `lsof -i :5601` |
| « ClamAV : chargement des signatures… » | Normal pendant ~1 min après le démarrage de `clamd` |
| Aucune signature ClamAV | `siemctl update-signatures` |
| Rien n'est détecté sur Bureau/Documents | Donner l'[accès complet au disque](#accès-complet-au-disque-recommandé) |
| Mot de passe perdu | `siemctl reset-password` |
| Erreur après mise à jour de Python (Homebrew) | `rm -rf .venv && ./scripts/install.sh` |

## Désinstallation

```bash
./siemctl uninstall      # retire les services launchd et l'application
rm -rf ~/SentinelSIEM    # (optionnel) supprime aussi les données
```

## Limites connues

- L'agent tourne avec les droits de l'utilisateur (pas root) : la vue réseau ne montre que les
  connexions de ses processus, et certains journaux/fichiers système restent invisibles.
- osquery et la détection de CVE ne sont pas inclus ; le module SCA signale les mises à jour macOS
  et Homebrew en attente.
- Apple Silicon uniquement (chemins `/opt/homebrew`).

---

<div align="center">
<sub>Projet privé — usage interne. Voir <a href="LICENSE">LICENSE</a> · <a href="CHANGELOG.md">CHANGELOG</a>.</sub>
</div>
