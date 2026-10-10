"""Référentiel MITRE ATT&CK (sous-ensemble pertinent pour macOS)."""

TACTICS = [
    ("TA0001", "Initial Access"),
    ("TA0002", "Execution"),
    ("TA0003", "Persistence"),
    ("TA0004", "Privilege Escalation"),
    ("TA0005", "Defense Evasion"),
    ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"),
    ("TA0009", "Collection"),
    ("TA0011", "Command and Control"),
    ("TA0010", "Exfiltration"),
    ("TA0040", "Impact"),
]

T = {
    "T1078": ("Valid Accounts", ["Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion"]),
    "T1189": ("Drive-by Compromise", ["Initial Access"]),
    "T1200": ("Hardware Additions", ["Initial Access"]),
    "T1566.001": ("Phishing: Spearphishing Attachment", ["Initial Access"]),
    "T1059.002": ("Command and Scripting: AppleScript", ["Execution"]),
    "T1059.004": ("Command and Scripting: Unix Shell", ["Execution"]),
    "T1059.006": ("Command and Scripting: Python", ["Execution"]),
    "T1204.002": ("User Execution: Malicious File", ["Execution"]),
    "T1569.001": ("System Services: Launchctl", ["Execution"]),
    "T1543.001": ("Create/Modify System Process: Launch Agent", ["Persistence", "Privilege Escalation"]),
    "T1543.004": ("Create/Modify System Process: Launch Daemon", ["Persistence", "Privilege Escalation"]),
    "T1053.003": ("Scheduled Task: Cron", ["Execution", "Persistence", "Privilege Escalation"]),
    "T1546.004": ("Event Triggered Execution: Unix Shell Config Modification", ["Persistence", "Privilege Escalation"]),
    "T1547.015": ("Boot or Logon Autostart: Login Items", ["Persistence", "Privilege Escalation"]),
    "T1136.001": ("Create Account: Local Account", ["Persistence"]),
    "T1098": ("Account Manipulation", ["Persistence", "Privilege Escalation"]),
    "T1098.004": ("Account Manipulation: SSH Authorized Keys", ["Persistence", "Privilege Escalation"]),
    "T1548.003": ("Abuse Elevation Control: Sudo and Sudo Caching", ["Privilege Escalation", "Defense Evasion"]),
    "T1553.001": ("Subvert Trust Controls: Gatekeeper Bypass", ["Defense Evasion"]),
    "T1562.001": ("Impair Defenses: Disable or Modify Tools", ["Defense Evasion"]),
    "T1562.004": ("Impair Defenses: Disable or Modify System Firewall", ["Defense Evasion"]),
    "T1564.001": ("Hide Artifacts: Hidden Files and Directories", ["Defense Evasion"]),
    "T1070.004": ("Indicator Removal: File Deletion", ["Defense Evasion"]),
    "T1070.002": ("Indicator Removal: Clear Linux or Mac System Logs", ["Defense Evasion"]),
    "T1027": ("Obfuscated Files or Information", ["Defense Evasion"]),
    "T1036": ("Masquerading", ["Defense Evasion"]),
    "T1222.002": ("File Permissions Modification: Linux and Mac", ["Defense Evasion"]),
    "T1110": ("Brute Force", ["Credential Access"]),
    "T1110.001": ("Brute Force: Password Guessing", ["Credential Access"]),
    "T1555.001": ("Credentials from Password Stores: Keychain", ["Credential Access"]),
    "T1555.003": ("Credentials from Web Browsers", ["Credential Access"]),
    "T1056.002": ("Input Capture: GUI Input Capture", ["Collection", "Credential Access"]),
    "T1539": ("Steal Web Session Cookie", ["Credential Access"]),
    "T1552.001": ("Unsecured Credentials: Credentials In Files", ["Credential Access"]),
    "T1082": ("System Information Discovery", ["Discovery"]),
    "T1046": ("Network Service Discovery", ["Discovery"]),
    "T1087.001": ("Account Discovery: Local Account", ["Discovery"]),
    "T1518.001": ("Security Software Discovery", ["Discovery"]),
    "T1021.004": ("Remote Services: SSH", ["Lateral Movement"]),
    "T1021.005": ("Remote Services: VNC", ["Lateral Movement"]),
    "T1113": ("Screen Capture", ["Collection"]),
    "T1115": ("Clipboard Data", ["Collection"]),
    "T1560.001": ("Archive Collected Data: Archive via Utility", ["Collection"]),
    "T1071.001": ("Application Layer Protocol: Web Protocols", ["Command and Control"]),
    "T1571": ("Non-Standard Port", ["Command and Control"]),
    "T1105": ("Ingress Tool Transfer", ["Command and Control"]),
    "T1090.003": ("Proxy: Multi-hop Proxy", ["Command and Control"]),
    "T1048": ("Exfiltration Over Alternative Protocol", ["Exfiltration"]),
    "T1496": ("Resource Hijacking", ["Impact"]),
    "T1486": ("Data Encrypted for Impact", ["Impact"]),
    "T1565.001": ("Data Manipulation: Stored Data Manipulation", ["Impact"]),
    "T1485": ("Data Destruction", ["Impact"]),
}


def technique(tid: str):
    name, tactics = T.get(tid, (tid, []))
    return {"id": tid, "name": name, "tactics": tactics}


def tactics_for(ids):
    out = []
    for tid in ids:
        for t in T.get(tid, ("", []))[1]:
            if t not in out:
                out.append(t)
    return out
