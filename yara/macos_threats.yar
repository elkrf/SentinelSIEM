/*
   SentinelSIEM — règles YARA orientées macOS
   meta.severity : critical | high | medium | low

   Variables externes fournies par le scanner : filename, extension (sans le point, en minuscules).
   En ligne de commande : yara -d filename=x -d extension=sh macos_threats.yar <fichier>

   Principe anti-faux-positifs : les règles « texte » ne s'appliquent qu'à du contenu réellement
   exécutable (Mach-O, script avec shebang, AppleScript compilé, extension de script). Une doc, un
   JSON, une conversation ou un fichier de règles qui *cite* un malware ne déclenche rien.
*/

private rule IsMachO
{
    condition:
        uint32(0) == 0xfeedfacf or uint32(0) == 0xcffaedfe or uint32(0) == 0xfeedface or
        uint32(0) == 0xcefaedfe or uint32(0) == 0xbebafeca or uint32(0) == 0xcafebabe
}

private rule IsScript
{
    condition:
        uint16(0) == 0x2123 or                 // "#!" (shebang)
        uint32(0) == 0x64736146 or             // "Fasd" : AppleScript compilé (.scpt)
        extension matches /^(sh|bash|zsh|ksh|command|tool|py|pyw|pl|rb|php\d?|phtml|jsp|jspx|asp|aspx|scpt|applescript|ps1|vbs|bat|cmd)$/
}

private rule IsReferenceText
{
    condition:
        extension matches /^(md|markdown|rst|txt|log|json|jsonl|ndjson|ya?ml|yar|yara|rules?|html?|xml|csv|tsv|pdf|ipynb)$/
}

rule EICAR_Test_File
{
    meta:
        description = "Fichier de test antivirus EICAR"
        severity = "low"
        family = "Test"
    strings:
        $a = { 58 35 4F 21 50 25 40 41 50 5B 34 5C 50 5A 58 35 34 28 50 5E 29 37 43 43 29 37 7D 24 45 49 43 41 52 }
    condition:
        $a at 0
}

rule MacOS_Stealer_AMOS
{
    meta:
        description = "Infostealer Atomic macOS Stealer (AMOS) / variantes"
        severity = "critical"
        family = "AMOS"
    strings:
        $s1 = "display dialog" ascii nocase
        $s2 = "hidden answer" ascii nocase
        $s3 = "System Preferences" ascii
        $s4 = "dscl /Local/Default -authonly" ascii
        $s5 = "login.keychain-db" ascii
        $s6 = "Cookies.binarycookies" ascii
        $s7 = "/Library/Application Support/Google/Chrome/" ascii
        $s8 = "Exodus" ascii
        $s9 = "Electrum" ascii
        $s10 = "MetaMask" ascii nocase
        $s11 = "FileGrabber" ascii
        $s12 = "/tmp/out.zip" ascii
        $s13 = "ditto -c -k --sequesterRsrc" ascii
    condition:
        filesize < 30MB and (IsMachO or IsScript) and (
            ($s1 and $s2 and ($s4 or $s5)) or
            (5 of ($s*))
        )
}

rule MacOS_Stealer_Generic_Browser_Wallets
{
    meta:
        description = "Collecte de mots de passe navigateurs et portefeuilles crypto"
        severity = "high"
        family = "Stealer"
    strings:
        $b1 = "Login Data" ascii wide
        $b2 = "Web Data" ascii wide
        $b3 = "cookies.sqlite" ascii wide
        $b4 = "logins.json" ascii wide
        $b5 = "key4.db" ascii wide
        $w1 = "wallet.dat" ascii wide
        $w2 = "Exodus/exodus.wallet" ascii wide
        $w3 = "atomic/Local Storage" ascii wide
        $w4 = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii wide  // ID extension MetaMask
        $w5 = "bfnaelmomeimhlpmgjnjophhpkkoljpa" ascii wide  // ID extension Phantom
        $k1 = "login.keychain" ascii wide
        $x1 = "api.telegram.org/bot" ascii wide
        $x2 = "/sendDocument" ascii wide
    condition:
        filesize < 50MB and (IsMachO or IsScript) and (2 of ($b*)) and (1 of ($w*) or $k1) and (1 of ($x*) or 3 of ($w*))
}

rule MacOS_Fake_Password_Prompt_Script
{
    meta:
        description = "Script AppleScript demandant un mot de passe (hameçonnage local)"
        severity = "high"
        family = "Phishing"
    strings:
        $a = "display dialog" ascii nocase
        $b = "hidden answer" ascii nocase
        $c = /(password|mot de passe|passwd)/ nocase
    condition:
        filesize < 5MB and IsScript and all of them
}

rule Unix_Reverse_Shell_Script
{
    meta:
        description = "Script contenant un reverse shell"
        severity = "critical"
        family = "ReverseShell"
    strings:
        $r1 = /(ba|z)?sh\s+-i\s*[<>&0-9 ]*\/dev\/tcp\// ascii
        $r2 = /\bnc(at)?\b[^\n]{0,60}\s-e\s+\/bin\/(ba|z)?sh/ ascii
        $r3 = /mkfifo[^\n]{0,80}\bnc\b/ ascii
        $r4 = /socket\.socket\([^\n]{0,200}\.connect\([^\n]{0,200}(dup2|pty\.spawn|subprocess)/ ascii
        $r5 = /socat[^\n]{0,80}exec:[^\n]{0,20}(ba|z)?sh/ ascii nocase
        $r6 = /use Socket;[^\x00]{0,400}exec\s*\(?\s*["']\/bin\/(ba|z)?sh/ ascii
        $r7 = /fsockopen\([^\n]{0,100}(exec|shell_exec|system|proc_open)/ ascii
    condition:
        filesize < 2MB and IsScript and any of them
}

rule Download_And_Execute_Dropper
{
    meta:
        description = "Dropper : téléchargement puis exécution / contournement Gatekeeper"
        severity = "high"
        family = "Dropper"
    strings:
        $d1 = /curl\s+[^\n|]{0,200}\|\s*(ba|z)?sh/ ascii
        $d2 = /curl\s+[^\n]{0,200}-o\s+\/(private\/)?tmp\/[^\n]{0,100}(chmod\s+\+x|&&\s*\/tmp)/ ascii
        $d3 = "xattr -c" ascii
        $d4 = /xattr\s+-[rd]+\s+com\.apple\.quarantine/ ascii
        $d5 = "spctl --master-disable" ascii
        $d6 = /base64\s+(-d|-D|--decode)[^\n]{0,80}\|\s*(ba|z)?sh/ ascii
        $e1 = "osascript" ascii
        $e2 = "launchctl load" ascii
        $e3 = "LaunchAgents" ascii
    condition:
        filesize < 10MB and IsScript and (
            $d6 or
            ($d2) or
            (($d1 or $d2) and ($d3 or $d4 or $d5)) or
            (($d1 or $d2) and $e2 and $e3) or
            ($d5 and ($e1 or $e2))
        )
}

rule MacOS_Persistence_Script
{
    meta:
        description = "Script installant une persistance LaunchAgent/LaunchDaemon"
        severity = "medium"
        family = "Persistence"
    strings:
        $p1 = "Library/LaunchAgents" ascii
        $p2 = "Library/LaunchDaemons" ascii
        $p3 = "RunAtLoad" ascii
        $p4 = /launchctl\s+(load|bootstrap)/ ascii
        $p5 = "KeepAlive" ascii
        $x1 = /curl\s+-[a-zA-Z]*\s+http/ ascii
        $x2 = "/Users/Shared/" ascii
        $x3 = /\/(private\/)?tmp\/\./ ascii
    condition:
        filesize < 5MB and IsScript and ($p1 or $p2) and $p3 and ($p4 or $p5) and any of ($x*)
}

rule CryptoMiner_XMRig
{
    meta:
        description = "Cryptomineur (XMRig / RandomX / Stratum)"
        severity = "high"
        family = "CoinMiner"
    strings:
        $m1 = "stratum+tcp://" ascii nocase
        $m2 = "stratum+ssl://" ascii nocase
        $m3 = "xmrig" ascii nocase
        $m4 = "randomx" ascii nocase
        $m5 = "--donate-level" ascii
        $m6 = "cryptonight" ascii nocase
        $m7 = "\"coin\": \"monero\"" ascii nocase
        $m8 = "pool.minexmr" ascii nocase
        $m9 = "supportxmr.com" ascii nocase
        $m10 = "nanopool.org" ascii nocase
    condition:
        filesize < 30MB and (IsMachO or IsScript) and 3 of them
}

rule Ransomware_Note
{
    meta:
        description = "Note de rançon"
        severity = "critical"
        family = "Ransomware"
    strings:
        $n1 = "your files have been encrypted" ascii wide nocase
        $n2 = "vos fichiers ont été chiffrés" ascii wide nocase
        $n3 = "to decrypt your files" ascii wide nocase
        $n4 = "bitcoin" ascii wide nocase
        $n5 = /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/ ascii
        $n6 = ".onion" ascii wide nocase
        $n7 = "private key" ascii wide nocase
        $n8 = "do not rename" ascii wide nocase
        $z1 = /\n\s*strings:\s*\n/ ascii     // source de règles YARA (qui cite les phrases ci-dessus)
        $z2 = /\n\s*condition:\s*\n/ ascii
    condition:
        filesize < 1MB and not ($z1 and $z2) and not IsMachO and not (extension matches /^(md|markdown|rst|json|jsonl|ya?ml|yar|yara|ipynb)$/) and (1 of ($n1, $n2, $n3)) and 2 of ($n4, $n5, $n6, $n7, $n8)
}

rule Ransomware_Encryptor_Script
{
    meta:
        description = "Script de chiffrement massif de fichiers"
        severity = "critical"
        family = "Ransomware"
    strings:
        $a = /find\s+[^\n]{0,80}(Documents|Desktop|Pictures|\$HOME|~)[^\n]{0,200}(openssl\s+enc|gpg\s+-c)/ ascii
        $b = /openssl\s+enc\s+-aes-256[^\n]{0,200}&&\s*rm\s/ ascii
        $c = "Fernet(" ascii
        $d = "os.walk(" ascii
        $e = ".encrypted" ascii
    condition:
        filesize < 5MB and IsScript and ($a or $b or ($c and $d and $e))
}

rule Webshell_Generic
{
    meta:
        description = "Webshell PHP / JSP"
        severity = "high"
        family = "Webshell"
    strings:
        $p1 = /eval\s*\(\s*(base64_decode|gzinflate|str_rot13|gzuncompress)\s*\(/ ascii nocase
        $p2 = /(system|shell_exec|passthru|exec|popen)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ ascii nocase
        $p3 = /assert\s*\(\s*\$_(GET|POST|REQUEST)/ ascii nocase
        $p4 = "Runtime.getRuntime().exec(request.getParameter" ascii
        $p5 = /preg_replace\s*\(\s*['"][^'"]*\/e['"]/ ascii
    condition:
        filesize < 2MB and IsScript and any of them
}

rule Python_Obfuscated_Loader
{
    meta:
        description = "Chargeur Python obfusqué (exec + décodage)"
        severity = "high"
        family = "Loader"
    strings:
        $a = /exec\s*\(\s*(base64\.b64decode|zlib\.decompress|marshal\.loads|bytes\.fromhex|codecs\.decode)/ ascii
        $b = /__import__\(\s*['"](base64|zlib|marshal)['"]\s*\)\.(b64decode|decompress|loads)/ ascii
        $c = /exec\(\s*['"][A-Za-z0-9+\/=]{300,}/ ascii
    condition:
        filesize < 10MB and IsScript and any of them
}

rule MacOS_Keylogger_EventTap
{
    meta:
        description = "Capture clavier via CGEventTap (keylogger potentiel)"
        severity = "medium"
        family = "Keylogger"
    strings:
        $a = "CGEventTapCreate" ascii
        $c = "CGEventKeyboardGetUnicodeString" ascii
        $d = /key ?logger|keystroke ?log|keystrokes\.(txt|log)/ nocase
        $e = "IOHIDManagerRegisterInputValueCallback" ascii
        $x1 = "/sendDocument" ascii
        $x2 = /https?:\/\/[^\x00]{4,80}\/(upload|log|keys)/ ascii
    condition:
        // Un simple raccourci clavier global (CGEventTap seul) n'est pas suspect :
        // on exige la lecture du texte tapé + un indice de journalisation ou d'envoi.
        IsMachO and filesize < 20MB and ($a or $e) and $c and ($d or any of ($x*))
}

rule MacOS_Backdoor_Indicators
{
    meta:
        description = "Indicateurs de porte dérobée macOS (RAT)"
        severity = "high"
        family = "Backdoor"
    strings:
        $a1 = "/usr/sbin/screencapture" ascii
        $a2 = "/usr/bin/osascript" ascii
        $a3 = "launchctl load" ascii
        $a4 = "Library/LaunchAgents" ascii
        $a5 = "kSecClassGenericPassword" ascii
        $a6 = "/bin/sh -c" ascii
        $n1 = "beacon" ascii nocase
        $n2 = "heartbeat" ascii nocase
        $n3 = "reverse" ascii nocase
        $n4 = "/upload" ascii
        $n5 = "/download" ascii
        $n6 = "keylog" ascii nocase
    condition:
        IsMachO and filesize < 20MB and 4 of ($a*) and 3 of ($n*)
}

rule Hacktool_Mimikatz_Like
{
    meta:
        description = "Outil de vol d'identifiants (chainbreaker, mimikatz, lazagne)"
        severity = "high"
        family = "Hacktool"
    strings:
        $a = "chainbreaker" ascii nocase
        $b = "mimikatz" ascii nocase
        $c = "lazagne" ascii nocase
        $d = "dump_keychain_passwords" ascii
        $e = "sekurlsa::" ascii
    condition:
        filesize < 50MB and (IsMachO or IsScript) and not IsReferenceText and (2 of them or $e or ($d and IsScript))
}
