#!/usr/bin/with-contenv bashio
set -euo pipefail

echo "[info] Starting Household Tool on port 8099"
cd /app
python3 main.py
