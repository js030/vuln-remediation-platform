#!/bin/bash
echo "[RESET]"

# 1. Zuerst alle unstaged Changes stashen (Sicherheit)
git stash

# 2. Zu main wechseln und aktualisieren
git checkout main -q
git pull --rebase origin main -q

# 3. Manifeste zurücksetzen
sed -i 's/image: nginx.*/image: nginx:1.14.0/g' manifests/base/01-base.yaml
sed -i 's/image: httpd.*/image: httpd:2.4.49/g' manifests/base/04-additional-vuln-apps.yaml
sed -i 's/image: redis.*/image: redis:5.0.9/g' manifests/base/04-additional-vuln-apps.yaml

# 4. Committen und pushen
git add manifests/base/01-base.yaml manifests/base/04-additional-vuln-apps.yaml
git commit -m "chore: reset demo manifests to vulnerable state" -q
git push origin main -q

# 5. Stash aufräumen (falls es Konflikte gab, diese manuell auflösen)
if git stash list | grep -q .; then
    echo "[WARN] Local changes were stashed. Run 'git stash pop' if needed."
fi

echo "[DONE]"
