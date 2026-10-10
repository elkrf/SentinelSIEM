#!/bin/bash
# SentinelSIEM — installation / réinstallation (idempotent)
set -e
DIR="$(cd "$(dirname "$0")/.." && pwd)"
LA="$HOME/Library/LaunchAgents"
BREW=/opt/homebrew/bin/brew
echo "==> Dépendances Homebrew"
for p in python@3.12 clamav yara; do $BREW list "$p" >/dev/null 2>&1 || $BREW install "$p"; done

echo "==> Configuration ClamAV"
E=/opt/homebrew/etc/clamav
mkdir -p /opt/homebrew/var/lib/clamav /opt/homebrew/var/run/clamav /opt/homebrew/var/log/clamav
if [ ! -f $E/freshclam.conf ]; then
  sed -e 's/^Example/#Example/' $E/freshclam.conf.sample > $E/freshclam.conf
  printf 'DatabaseDirectory /opt/homebrew/var/lib/clamav\nUpdateLogFile /opt/homebrew/var/log/clamav/freshclam.log\nDatabaseMirror database.clamav.net\nNotifyClamd /opt/homebrew/etc/clamav/clamd.conf\n' >> $E/freshclam.conf
fi
if [ ! -f $E/clamd.conf ]; then
  sed -e 's/^Example/#Example/' $E/clamd.conf.sample > $E/clamd.conf
  printf 'LocalSocket /opt/homebrew/var/run/clamav/clamd.sock\nLocalSocketMode 660\nDatabaseDirectory /opt/homebrew/var/lib/clamav\nLogFile /opt/homebrew/var/log/clamav/clamd.log\nStreamMaxLength 200M\nMaxFileSize 200M\nMaxScanSize 400M\nSelfCheck 3600\nForeground yes\n' >> $E/clamd.conf
fi
ls /opt/homebrew/var/lib/clamav/main.c?d >/dev/null 2>&1 || /opt/homebrew/bin/freshclam

echo "==> Environnement Python"
[ -x "$DIR/.venv/bin/python" ] || /opt/homebrew/bin/python3.12 -m venv "$DIR/.venv"
"$DIR/.venv/bin/pip" install -q --upgrade pip
"$DIR/.venv/bin/pip" install -q -r "$DIR/requirements.txt"

echo "==> Services launchd"
mkdir -p "$LA" "$DIR/data/logs"
cat > "$LA/com.sentinelsiem.clamd.plist" <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.sentinelsiem.clamd</string>
  <key>ProgramArguments</key><array>
    <string>/opt/homebrew/sbin/clamd</string><string>--config-file=/opt/homebrew/etc/clamav/clamd.conf</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Background</string>
  <key>LowPriorityIO</key><true/>
  <key>StandardErrorPath</key><string>$DIR/data/logs/clamd.err</string>
</dict></plist>
PL
cat > "$LA/com.sentinelsiem.agent.plist" <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.sentinelsiem.agent</string>
  <key>ProgramArguments</key><array>
    <string>$DIR/.venv/bin/python</string><string>-m</string><string>uvicorn</string><string>siem.app:app</string>
    <string>--host</string><string>127.0.0.1</string><string>--port</string><string>5601</string><string>--log-level</string><string>warning</string>
  </array>
  <key>WorkingDirectory</key><string>$DIR/backend</string>
  <key>EnvironmentVariables</key><dict>
    <key>PATH</key><string>/opt/homebrew/bin:/opt/homebrew/sbin:/usr/bin:/bin:/usr/sbin:/sbin</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>5</integer>
  <key>StandardOutPath</key><string>$DIR/data/logs/service.log</string>
  <key>StandardErrorPath</key><string>$DIR/data/logs/service.log</string>
</dict></plist>
PL

echo "==> Application SentinelSIEM.app"
APP="$HOME/Applications/SentinelSIEM.app"
mkdir -p "$HOME/Applications"
rm -rf "$APP"
osacompile -o "$APP" -e "do shell script \"'$DIR/siemctl' ensure\"" -e "delay 1" -e "open location \"http://localhost:5601\""
TMP=$(mktemp -d)
if qlmanage -t -s 1024 -o "$TMP" "$DIR/frontend/favicon.svg" >/dev/null 2>&1 && [ -f "$TMP/favicon.svg.png" ]; then
  mkdir -p "$TMP/icon.iconset"
  for s in 16 32 128 256 512; do
    sips -z $s $s "$TMP/favicon.svg.png" --out "$TMP/icon.iconset/icon_${s}x${s}.png" >/dev/null
    sips -z $((s*2)) $((s*2)) "$TMP/favicon.svg.png" --out "$TMP/icon.iconset/icon_${s}x${s}@2x.png" >/dev/null
  done
  iconutil -c icns "$TMP/icon.iconset" -o "$APP/Contents/Resources/applet.icns" && touch "$APP"
fi
rm -rf "$TMP"

echo "==> Démarrage"
"$DIR/siemctl" restart
sleep 4
"$DIR/siemctl" status
[ -f "$DIR/data/admin_password.txt" ] && cat "$DIR/data/admin_password.txt"
