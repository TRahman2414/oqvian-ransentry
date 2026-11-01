#!/usr/bin/env bash
set -euo pipefail
curl --fail --silent --show-error -X POST http://127.0.0.1:8011/api/demo/reset
printf '\n'
