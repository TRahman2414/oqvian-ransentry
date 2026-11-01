#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/backend"
uv sync
cd "$ROOT/frontend"
npm install
printf '\nOQVIAN RANSENTRY dependencies installed. Run ./scripts/start-dev.sh\n'
