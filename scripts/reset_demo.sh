#!/usr/bin/env bash
set -euo pipefail

echo "[RESET] Restoring all test images to their defined vulnerable demo versions..."

# This script is intended only for the controlled PoC/demo environment.
# It intentionally restores vulnerable image versions.

if [[ -n "$(git status --porcelain)" ]]; then
  echo "[ERROR] Working tree is not clean. Please review, commit, restore, or stash changes first:"
  git status --short
  exit 1
fi

git switch main -q
git pull --ff-only origin main -q

# ------------------------------------------------------------
# Core single-container Deployment scenarios
# ------------------------------------------------------------

sed -i -E \
  's|^([[:space:]]*image:[[:space:]]*)nginx:[^[:space:]#]+|\1nginx:1.14.0|' \
  manifests/base/01-base.yaml

sed -i -E \
  's|^([[:space:]]*image:[[:space:]]*)redis:[^[:space:]#]+|\1redis:5.0.9|' \
  manifests/base/04-additional-vuln-apps.yaml

sed -i -E \
  's|^([[:space:]]*image:[[:space:]]*)httpd:[^[:space:]#]+|\1httpd:2.4.49|' \
  manifests/base/04-additional-vuln-apps.yaml

# ------------------------------------------------------------
# Multi-container and init-container scenarios
# ------------------------------------------------------------

if [[ -f manifests/base/08-multi-container-apps.yaml ]]; then
  sed -i -E \
    's|^([[:space:]]*image:[[:space:]]*)nginx:[^[:space:]#]+|\1nginx:1.14.0|' \
    manifests/base/08-multi-container-apps.yaml

  sed -i -E \
    's|^([[:space:]]*image:[[:space:]]*)redis:[^[:space:]#]+|\1redis:5.0.9|' \
    manifests/base/08-multi-container-apps.yaml

  sed -i -E \
    's|^([[:space:]]*image:[[:space:]]*)alpine:[^[:space:]#]+|\1alpine:3.8|' \
    manifests/base/08-multi-container-apps.yaml

  sed -i -E \
    's|^([[:space:]]*image:[[:space:]]*)busybox:[^[:space:]#]+|\1busybox:1.28.0|' \
    manifests/base/08-multi-container-apps.yaml

  sed -i -E \
    's|^([[:space:]]*image:[[:space:]]*)httpd:[^[:space:]#]+|\1httpd:2.4.49|' \
    manifests/base/08-multi-container-apps.yaml
fi

# ------------------------------------------------------------
# StatefulSet and DaemonSet scenarios
# ------------------------------------------------------------

if [[ -f manifests/base/09-statefulsets.yaml ]]; then
  sed -i -E \
    's|^([[:space:]]*image:[[:space:]]*)mongo:[^[:space:]#]+|\1mongo:3.6.0|' \
    manifests/base/09-statefulsets.yaml

  sed -i -E \
    's|^([[:space:]]*image:[[:space:]]*)prom/node-exporter:[^[:space:]#]+|\1prom/node-exporter:v1.0.1|' \
    manifests/base/09-statefulsets.yaml
fi

git add manifests/base/

if git diff --cached --quiet; then
  echo "[RESET] All manifests are already in the configured demo state."
else
  git commit -m "chore: reset all test images to vulnerable demo state" -q
  git push origin main -q
  echo "[RESET] Vulnerable demo state committed and pushed to main."
fi

echo "[DONE]"
