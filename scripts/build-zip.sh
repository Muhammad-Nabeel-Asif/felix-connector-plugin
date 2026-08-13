#!/usr/bin/env bash
# Build the merchant-facing plugin ZIP. runner.php MUST be included —
# a ZIP that omitted it 404'd on staging and broke DISABLE_WP_CRON fallback.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
php "${ROOT}/scripts/build-zip.php"
