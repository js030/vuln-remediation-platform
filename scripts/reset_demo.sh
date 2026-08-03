#!/bin/bash
echo "[RESET]"
git checkout main -q
git pull origin main -q

# Nur die tatsächlich relevanten Demo-Dateien zurücksetzen
sed -i 's/image: nginx.*/image: nginx:1.14.0/g' manifests/base/01-base.yaml
sed -i 's/image: httpd.*/image: httpd:2.4.49/g' manifests/base/04-additional-vuln-apps.yaml
sed -i 's/image: redis.*/image: redis:5.0.9/g' manifests/base/04-additional-vuln-apps.yaml

git add manifests/base/01-base.yaml manifests/base/04-additional-vuln-apps.yaml
git commit -m "chore: reset demo manifests to vulnerable state" -q
git push origin main -q
echo "[DONE]"
