#!/usr/bin/env bash
# Pull the latest main, rebuild the images on this server, and restart the stack.
# Usage:  ./deploy.sh
set -euo pipefail

cd "$(dirname "$0")"

COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.prod.yml)

if [[ ! -f .env ]]; then
    echo "ERROR: .env is missing. Copy .env.example to .env and fill in the secrets." >&2
    exit 1
fi

echo "==> git pull"
git pull --ff-only origin main

echo "==> build"
"${COMPOSE[@]}" build --pull

echo "==> up"
"${COMPOSE[@]}" up -d --remove-orphans

echo "==> prune dangling images"
docker image prune -f >/dev/null

echo "==> status"
"${COMPOSE[@]}" ps
