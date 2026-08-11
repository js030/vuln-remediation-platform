#!/usr/bin/env bash
set -euo pipefail

echo "[RESET] Restoring all test images to their defined vulnerable demo versions..."

# This script is for the controlled demo/test environment only.
# It intentionally restores vulnerable image versions.

# Do not continue if a manual or automated run has left local changes behind.
if [[ -n "$(git status --porcelain)" ]]; then
  echo "[ERROR] Working tree is not clean. Please review or commit/stash changes first:"
  git status --short
  exit 1
fi

# Always reset from the current main branch.
git switch main -q
git pull --ff-only origin main -q

# ------------------------------------------------------------
# Core supported remediation scenarios
# ------------------------------------------------------------

# 01-base.yaml
sed -i -E \
  's|^([[:space:]]*image:[[:space:]]*)nginx:[^[:space:]#]+|\1nginx:1.14.0|' \
  manifests/base/01-base.yaml

# 04-additional-vuln-apps.yaml
sed -i -E \
  's|^([[:space:]]*image:[[:space:]]*)redis:[^[:space:]#]+|\1redis:5.0.9|' \
  manifests/base/04-additional-vuln-apps.yaml

sed -i -E \
  's|^([[:space:]]*image:[[:space:]]*)httpd:[^[:space:]#]+|\1httpd:2.4.49|' \
  manifests/base/04-additional-vuln-apps.yaml

# ------------------------------------------------------------
# Additional image scenarios
# Note: Some of these are experimental. A reset does not mean
# that Trivy necessarily provides a valid fixed version.
# ------------------------------------------------------------

if [[ -f manifests/base/07-additional-test-apps.yaml ]]; then
  sed -i -E \
    's|^([[:space:]]*image:[[:space:]]*)postgres:[^[:space:]#]+|\1postgres:9.6.0|' \
    manifests/base/07-additional-test-apps.yaml

  sed -i -E \
    's|^([[:space:]]*image:[[:space:]]*)mysql:[^[:space:]#]+|\1mysql:5.6.0|' \
    manifests/base/07-additional-test-apps.yaml

  sed -i -E \
    's|^([[:space:]]*image:[[:space:]]*)node:[^[:space:]#]+|\1node:14.0.0|' \
    manifests/base/07-additional-test-apps.yaml

  sed -i -E \
    's|^([[:space:]]*image:[[:space:]]*)openjdk:[^[:space:]#]+|\1openjdk:8u0|' \
    manifests/base/07-additional-test-apps.yaml

  sed -i -E \
    's|^([[:space:]]*image:[[:space:]]*)python:[^[:space:]#]+|\1python:2.7.0|' \
    manifests/base/07-additional-test-apps.yaml

  sed -i -E \
    's|^([[:space:]]*image:[[:space:]]*)ubuntu:[^[:space:]#]+|\1ubuntu:16.04|' \
    manifests/base/07-additional-test-apps.yaml
fi

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
    's|^([[:space:]]*image:[[:space:]]*)prometheus/node-exporter:[^[:space:]#]+|\1prometheus/node-exporter:v0.15.0|' \
    manifests/base/09-statefulsets.yaml
fi

# Only commit if the reset actually changed files.
git add manifests/base/

if git diff --cached --quiet; then
  echo "[RESET] All manifests are already in the configured demo state."
else
  git commit -m "chore: reset all test images to vulnerable demo state" -q
  git push origin main -q
  echo "[RESET] Reset state committed and pushed to main."
fi

echo "[DONE]"
