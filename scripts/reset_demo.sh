#!/bin/bash

find manifests/base -type f -name "*.yaml" -exec sed -i 's/image: nginx:.*/image: nginx:1.14.0/g' {} +
find manifests/base -type f -name "*.yaml" -exec sed -i 's/image: redis:.*/image: redis:5.0.9/g' {} +
find manifests/base -type f -name "*.yaml" -exec sed -i 's/image: httpd:.*/image: httpd:2.4.49/g' {} +

git add manifests/base/
git commit -m "chore: reset demo environment to vulnerable state"
git push origin main
