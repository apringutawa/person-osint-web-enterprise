#!/usr/bin/env bash
set -euo pipefail
docker compose build
docker compose up -d
echo "UI  -> http://localhost:5173"
echo "API -> http://localhost:8000/docs"
echo "PhoneInfoga UI (opsional) -> http://localhost:8080"
