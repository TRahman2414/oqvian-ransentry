#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/backend"
uv run uvicorn app.main:app --host 127.0.0.1 --port 8011 --reload &
API_PID=$!
cd "$ROOT/frontend"
npm run dev -- --host 127.0.0.1 --port 4184 &
UI_PID=$!
cleanup() {
  kill "$API_PID" "$UI_PID" 2>/dev/null || true
  wait "$API_PID" "$UI_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM
printf 'Dashboard: http://127.0.0.1:4184\nAPI docs:  http://127.0.0.1:8011/docs\n'
wait
