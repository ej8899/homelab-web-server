#!/usr/bin/env bash
rsync -avz \
  --exclude ".git" \
  --exclude ".github" \
  --exclude "node_modules" \
  --exclude "vendor" \
  --exclude "README.md" \
  --exclude "zdeploy.sh" \
  ./  ej@192.168.1.214:/var/www/home.ejmedia.ca/public/
