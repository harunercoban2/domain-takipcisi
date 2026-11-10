#!/bin/bash
# Çift tıklayarak Domain Takipçisi'ni başlatır (macOS).
cd "$(dirname "$0")"
if ! command -v node >/dev/null 2>&1; then
  echo "Node.js bulunamadı. https://nodejs.org adresinden kurun (18 veya üstü)."
  read -n 1 -s -r -p "Kapatmak için bir tuşa basın…"
  exit 1
fi
PORT="${PORT:-3000}"
( sleep 1.5; open "http://localhost:$PORT" ) &
node server.js
