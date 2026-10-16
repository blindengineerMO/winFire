#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
command -v npx >/dev/null 2>&1
runner="${PLAYWRIGHT_CLI_WRAPPER:-$HOME/.codex/skills/playwright/scripts/playwright_cli.sh}"
export VIEWS_UI_PORT="${VIEWS_UI_PORT:-3320}"
task_session="views-performance-$$"
task_log="$(mktemp /tmp/winfire-views-ui.XXXXXX)"
node scripts/views-ui-fixture.mjs >"$task_log" 2>&1 &
task_pid=$!
cleanup(){ bash "$runner" --session "$task_session" close >/dev/null 2>&1 || true; kill "$task_pid" 2>/dev/null || true; wait "$task_pid" 2>/dev/null || true; rm -f "$task_log"; }
trap cleanup EXIT
for attempt in {1..80}; do
  if curl -fsS "http://127.0.0.1:$VIEWS_UI_PORT/api/v1/health" >/dev/null 2>&1; then break; fi
  if ! kill -0 "$task_pid" 2>/dev/null; then cat "$task_log"; exit 1; fi
  sleep .25
done
mkdir -p output/playwright
bash "$runner" --session "$task_session" open "http://127.0.0.1:$VIEWS_UI_PORT/login"
bash "$runner" --session "$task_session" run-code "$(cat scripts/views-ui-check.js)" | tee "$task_log.actions"
if rg -q '^### Error' "$task_log.actions"; then rm -f "$task_log.actions"; exit 1; fi
rm -f "$task_log.actions"
