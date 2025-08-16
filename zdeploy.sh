#!/usr/bin/env bash

#
# zdeploy.sh
#
# Purpose:
#   Push code from the dev server to the homelab web server (.214).
#   This copies new/changed files into the live site directory but does NOT delete
#   anything on the destination.
#
# Usage:
#   sh ./zdeploy.sh
#
# Notes:
#   - You will be prompted for the ej account password on .214 (unless we set auth key).
#   - Adjust the --exclude list as necessary.
#   - Run from the WEB PUBLIC of your project folder on .213 as it copies to the web PUBLIC on .214.
#

rsync -avz \
  --exclude ".git" \
  --exclude ".github" \
  --exclude "node_modules" \
  --exclude "vendor" \
  --exclude "README.md" \
  --exclude "zdeploy.sh" \
  ./  ej@192.168.1.214:/var/www/home.ejmedia.ca/public/
