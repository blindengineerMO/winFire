#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# Uses only a disposable fixture database and this script's own browser session.
runner="${PLAYWRIGHT_CLI_WRAPPER:-$HOME/.codex/skills/playwright/scripts/playwright_cli.sh}"
if [[ ! -f "$runner" ]]; then
  printf '%s\n' 'Set PLAYWRIGHT_CLI_WRAPPER to the installed playwright-cli wrapper.' >&2
  exit 1
fi
export AI_UI_PORT="${AI_UI_PORT:-3318}"
task_session="ai-delivery-$$"
task_log="$(mktemp /tmp/winfire-ai-ui-check.XXXXXX)"
node scripts/ai-ui-fixture.mjs >"$task_log" 2>&1 &
task_pid=$!
cleanup(){ bash "$runner" --session "$task_session" close >/dev/null 2>&1 || true; kill "$task_pid" 2>/dev/null || true; wait "$task_pid" 2>/dev/null || true; }
trap cleanup EXIT
for attempt in {1..40}; do
  if curl -fsS "http://127.0.0.1:$AI_UI_PORT/api/v1/health" >/dev/null; then break; fi
  if ! kill -0 "$task_pid" 2>/dev/null; then cat "$task_log"; exit 1; fi
  sleep .25
done
bash "$runner" --session "$task_session" open "http://127.0.0.1:$AI_UI_PORT/ai-usage"
bash "$runner" --session "$task_session" run-code "$(cat scripts/ai-ui-check.js)" | tee "$task_log.actions"
if rg -q '^### Error' "$task_log.actions"; then exit 1; fi
