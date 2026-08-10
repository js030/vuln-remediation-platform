#!/bin/bash
echo "[RESET]"

git stash 2>/dev/null || true
git checkout main -q
git pull --rebase origin main -q

# Core Demo Apps
sed -i 's/image: nginx.*/image: nginx:1.14.0/g' manifests/base/01-base.yaml
sed -i 's/image: httpd.*/image: httpd:2.4.49/g' manifests/base/04-additional-vuln-apps.yaml
sed -i 's/image: redis.*/image: redis:5.0.9/g' manifests/base/04-additional-vuln-apps.yaml

# Additional Test Apps
sed -i 's/image: postgres.*/image: postgres:9.6.0/g' manifests/base/07-additional-test-apps.yaml
sed -i 's/image: mysql.*/image: mysql:5.6.0/g' manifests/base/07-additional-test-apps.yaml
sed -i 's/image: node.*/image: node:14.0.0/g' manifests/base/07-additional-test-apps.yaml
sed -i 's/image: openjdk.*/image: openjdk:8u0/g' manifests/base/07-additional-test-apps.yaml
sed -i 's/image: python.*/image: python:2.7.0/g' manifests/base/07-additional-test-apps.yaml
sed -i 's/image: ubuntu.*/image: ubuntu:16.04/g' manifests/base/07-additional-test-apps.yaml

# Multi-Container Apps
sed -i 's/image: busybox.*/image: busybox:1.28.0/g' manifests/base/08-multi-container-apps.yaml
sed -i 's/image: alpine.*/image: alpine:3.8/g' manifests/base/08-multi-container-apps.yaml

# StatefulSets & DaemonSets
sed -i 's/image: mongo.*/image: mongo:3.6.0/g' manifests/base/09-statefulsets.yaml
sed -i 's/image: prometheus.*/image: prometheus\/node-exporter:v0.15.0/g' manifests/base/09-statefulsets.yaml

# Commit changes
git add manifests/base/
git commit -m "chore: reset all vulnerable images to initial state" -q
git push origin main -q

echo "[DONE]"
