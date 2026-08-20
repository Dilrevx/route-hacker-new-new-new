#!/usr/bin/env bash
set -euo pipefail

# Run native Codex Security or a local Codex-compatible wrapper over a blind
# repository queue. Queue rows must contain only scheduling metadata and must
# not include target paths, anchors, source/sink facts, or known findings.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

RUN_ROOT="${CODEX_SECURITY_RUN_ROOT:-${TMPDIR:-/tmp}/route-hacker-codex-security}"
CONTROL_ROOT="${CODEX_SECURITY_CONTROL_ROOT:-$RUN_ROOT/control}"
RUNTIME_ROOT="${CODEX_SECURITY_RUNTIME_ROOT:-$RUN_ROOT/runtime}"
CONTROL="$CONTROL_ROOT"
QUEUE="${CODEX_SECURITY_QUEUE:-$CONTROL/queue.jsonl}"
BATCH_DIR="${CODEX_SECURITY_BATCH_DIR:-$RUNTIME_ROOT/batch}"
SUMMARY_JSONL="${CODEX_SECURITY_RUN_RECORDS:-$CONTROL/run_records.jsonl}"
STATUS_TSV="${CODEX_SECURITY_STATUS_TSV:-$CONTROL/status.tsv}"
REPO_CACHE="${CODEX_SECURITY_REPO_CACHE:-$RUNTIME_ROOT/repo-cache}"
LOG_DIR="${CODEX_SECURITY_LOG_DIR:-$CONTROL/logs}"
STATE_DIR="${CODEX_SECURITY_STATE_DIR:-$CONTROL/state}"
RUN_LOCK_DIR="$CONTROL/runner.lock"
QUOTA_SENTINEL="$STATE_DIR/quota_blocked"
AUTH_SENTINEL="$STATE_DIR/auth_blocked"

CODEX_SECURITY_PKG="${CODEX_SECURITY_PKG:-@openai/codex-security@0.1.12}"
CODEX_MODEL="${CODEX_SECURITY_MODEL:-gpt-5.6-terra}"
CODEX_EFFORT="${CODEX_SECURITY_EFFORT:-high}"
USE_TRAEX_WRAPPER="${CODEX_SECURITY_USE_TRAEX_WRAPPER:-0}"
WRAPPER="${CODEX_SECURITY_WRAPPER:-}"
TRAEX_BIN="${CODEX_SECURITY_TRAEX_BIN:-traex}"
PLUGIN_DIR="${CODEX_SECURITY_PLUGIN_DIR:-}"
MAX_NEW_CASES="${CODEX_SECURITY_MAX_NEW_CASES:-}"
OUTER_PARALLELISM="${CODEX_SECURITY_OUTER_PARALLELISM:-1}"

mkdir -p "$BATCH_DIR"/{inputs,outputs} "$REPO_CACHE" "$LOG_DIR" "$STATE_DIR"
chmod 700 "$CONTROL_ROOT" "$CONTROL" "$RUNTIME_ROOT" "$BATCH_DIR" \
  "$REPO_CACHE" "$LOG_DIR" "$STATE_DIR" 2>/dev/null || true

fail() {
  printf '%s\n' "$*" >&2
  exit 64
}

acquire_run_lock() {
  if mkdir "$RUN_LOCK_DIR" 2>/dev/null; then
    printf '%s\n' "$$" >"$RUN_LOCK_DIR/pid"
    trap 'rm -rf "$RUN_LOCK_DIR"' EXIT
    return 0
  fi

  local old_pid
  old_pid="$(cat "$RUN_LOCK_DIR/pid" 2>/dev/null || true)"
  if [[ -n "$old_pid" ]] && kill -0 "$old_pid" 2>/dev/null; then
    printf 'another runner is active: pid=%s lock=%s\n' "$old_pid" "$RUN_LOCK_DIR" >&2
    exit 75
  fi

  rm -rf "$RUN_LOCK_DIR"
  mkdir "$RUN_LOCK_DIR"
  printf '%s\n' "$$" >"$RUN_LOCK_DIR/pid"
  trap 'rm -rf "$RUN_LOCK_DIR"' EXIT
}

check_quota_guard() {
  if [[ "${CODEX_SECURITY_CONTINUE_AFTER_USAGE_LIMIT:-}" == "1" ]]; then
    return 0
  fi
  if [[ -f "$QUOTA_SENTINEL" ]]; then
    printf 'codex usage limit sentinel present: %s\n' "$QUOTA_SENTINEL" >&2
    cat "$QUOTA_SENTINEL" >&2 || true
    exit 76
  fi
}

check_auth_guard() {
  if [[ "${CODEX_SECURITY_CONTINUE_AFTER_AUTH_ERROR:-}" == "1" ]]; then
    return 0
  fi
  if [[ -f "$AUTH_SENTINEL" ]]; then
    printf 'codex auth error sentinel present: %s\n' "$AUTH_SENTINEL" >&2
    cat "$AUTH_SENTINEL" >&2 || true
    exit 77
  fi
}

append_summary() {
  local record="$1"
  printf '%s\n' "$record" >>"$SUMMARY_JSONL"
}

sha256_short() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 | cut -c1-16
  else
    sha256sum | cut -c1-16
  fi
}

json_get() {
  python3 -c 'import json,sys; print(json.loads(sys.argv[1])[sys.argv[2]])' "$1" "$2"
}

prepare_blind_repo() {
  local repo_url="$1"
  local revision="$2"
  local case_id="$3"
  local repo="$BATCH_DIR/inputs/$case_id/repo"
  local cache_key cache_repo

  if [[ -d "$repo/.git" ]] && \
     [[ "$(git -C "$repo" rev-parse HEAD 2>/dev/null || true)" == "$revision" ]] && \
     [[ -z "$(git -C "$repo" status --porcelain)" ]]; then
    printf '%s\n' "$repo"
    return 0
  fi

  cache_key="$(printf '%s' "$repo_url" | sha256_short)"
  cache_repo="$REPO_CACHE/$cache_key.git"
  if [[ ! -d "$cache_repo" ]]; then
    git init --quiet --bare "$cache_repo" || return 1
    git -C "$cache_repo" remote add origin "$repo_url" || return 1
  fi
  if ! git -C "$cache_repo" cat-file -e "$revision^{commit}" 2>/dev/null; then
    git -C "$cache_repo" fetch --quiet --no-tags --depth=1 origin "$revision" || return 1
  fi
  git -C "$cache_repo" update-ref "refs/heads/codex-security-cache-${revision:0:12}" \
    "$revision" || return 1

  rm -rf "$repo"
  mkdir -p "$(dirname "$repo")"
  git clone --quiet --no-checkout "$cache_repo" "$repo" || return 1
  git -C "$repo" checkout --quiet --detach "$revision" || return 1
  git -C "$repo" remote set-url origin "$repo_url" || return 1
  [[ "$(git -C "$repo" rev-parse HEAD 2>/dev/null)" == "$revision" ]] || return 1
  [[ -z "$(git -C "$repo" status --porcelain)" ]] || return 1
  printf '%s\n' "$repo"
}

write_status() {
  python3 - "$QUEUE" "$STATE_DIR" "$STATUS_TSV" <<'PY'
import json
import pathlib
import sys

queue_path, state_dir, status_path = map(pathlib.Path, sys.argv[1:])
rows = [json.loads(line) for line in queue_path.read_text().splitlines() if line.strip()]
with status_path.open("w", encoding="utf-8") as handle:
    handle.write("rank\tcase_id\tstate\tproject\tvulnerability_type\n")
    for row in rows:
        case_id = row["case_id"]
        state = "pending"
        for candidate in ("accepted", "partial", "failed", "stopped", "running", "prepared"):
            if (state_dir / f"{case_id}.{candidate}").exists():
                state = candidate
                break
        handle.write(
            f'{row["rank"]}\t{case_id}\t{state}\t'
            f'{row["repo_key"]}\t{row["vulnerability_type"]}\n'
        )
PY
}

run_case() {
  local row="$1"
  local rank case_id repo_url revision repo case_out out attempt_id log
  rank="$(json_get "$row" rank)"
  case_id="$(json_get "$row" case_id)"
  repo_url="$(json_get "$row" repo_url)"
  revision="$(json_get "$row" checkout_revision)"
  case_out="$BATCH_DIR/outputs/$case_id"
  log="$LOG_DIR/$case_id.log"

  if [[ -f "$STATE_DIR/$case_id.accepted" ||
        -f "$STATE_DIR/$case_id.partial" ||
        -f "$STATE_DIR/$case_id.failed" ||
        -f "$STATE_DIR/$case_id.stopped" ]]; then
    return 2
  fi

  rm -f "$STATE_DIR/$case_id.running"
  : >"$log"
  rm -f "$log.header"
  : >"$STATE_DIR/$case_id.prepared"
  write_status

  local prepare_start prepare_end prepare_status
  prepare_start="$(date +%s)"
  set +e
  repo="$(prepare_blind_repo "$repo_url" "$revision" "$case_id" 2>>"$log")"
  prepare_status=$?
  set -e
  prepare_end="$(date +%s)"
  if [[ "$prepare_status" -ne 0 ]]; then
    rm -f "$STATE_DIR/$case_id.prepared"
    : >"$STATE_DIR/$case_id.failed"
    append_summary "$(python3 - "$row" "$prepare_status" "$((prepare_end-prepare_start))" "$log" <<'PY'
import json, sys
row = json.loads(sys.argv[1])
print(json.dumps({
    "rank": row["rank"],
    "case_id": row["case_id"],
    "status": "source_prepare_failed",
    "exit_code": int(sys.argv[2]),
    "elapsed_seconds": int(sys.argv[3]),
    "log": sys.argv[4],
}, sort_keys=True))
PY
)"
    write_status
    return 0
  fi

  attempt_id="attempt_$(date -u +%Y%m%dT%H%M%SZ)_$$"
  out="$case_out/$attempt_id"
  mkdir -p "$out"
  chmod 700 "$case_out" "$out" 2>/dev/null || true
  rm -f "$STATE_DIR/$case_id.prepared"
  : >"$STATE_DIR/$case_id.running"
  write_status

  local -a cmd=(
    npx -y "$CODEX_SECURITY_PKG" scan "$repo"
    --model "$CODEX_MODEL"
    --effort "$CODEX_EFFORT"
    --headless
    --verbose
    --archive-existing
    --output-dir "$out"
  )

  {
    echo "RANK=$rank"
    echo "CASE_ID=$case_id"
    echo "REPO=$repo"
    echo "REVISION=$revision"
    echo "OUT=$out"
    echo "SCOPE=full_repository"
    echo "MODEL=$CODEX_MODEL"
    echo "EFFORT=$CODEX_EFFORT"
    if [[ "$USE_TRAEX_WRAPPER" == "1" ]]; then
      echo "CODEX_EXEC_MODE=traex-wrapper"
    else
      echo "CODEX_EXEC_MODE=native-codex"
    fi
    printf 'COMMAND='
    if [[ "$USE_TRAEX_WRAPPER" == "1" ]]; then
      printf '%q ' CODEX_CLI_PATH="$WRAPPER" CODEX_SECURITY_PLUGIN_DIR="$PLUGIN_DIR" \
        CODEX_SECURITY_TRAEX_BIN="$TRAEX_BIN" "${cmd[@]}"
    else
      printf '%q ' "${cmd[@]}"
    fi
    echo
  } >"$log.header"

  local start end status
  start="$(date +%s)"
  set +e
  if [[ "$USE_TRAEX_WRAPPER" == "1" ]]; then
    CODEX_CLI_PATH="$WRAPPER" \
    CODEX_SECURITY_PLUGIN_DIR="$PLUGIN_DIR" \
    CODEX_SECURITY_TRAEX_BIN="$TRAEX_BIN" \
      "${cmd[@]}" >>"$log" 2>&1
  else
    "${cmd[@]}" >>"$log" 2>&1
  fi
  status=$?
  set -e
  end="$(date +%s)"

  local record final_state
  record="$(python3 - "$row" "$status" "$out" "$log" "$((end-start))" <<'PY'
import json
import pathlib
import sys

row, status, out, log, elapsed = sys.argv[1:]
row = json.loads(row)
outp = pathlib.Path(out)
status = int(status)
has_core = all((outp / name).exists() for name in (
    "scan-manifest.json", "findings.json", "coverage.json"
))
record = {
    "rank": row["rank"],
    "case_id": row["case_id"],
    "status": "accepted" if status == 0 else ("partial_artifacts" if has_core else "failed"),
    "exit_code": status,
    "elapsed_seconds": int(elapsed),
    "output_dir": out,
    "log": log,
    "artifacts": {},
}

for name in ("report.md", "findings.json", "coverage.json", "scan-manifest.json", "exports/results.sarif"):
    path = outp / name
    record["artifacts"][name] = str(path) if path.exists() else None
try:
    findings = json.loads((outp / "findings.json").read_text())
    values = findings.get("findings", [])
    record["findings_total"] = len(values) if isinstance(values, list) else None
    severity_counts = {}
    for finding in values if isinstance(values, list) else []:
        severity = ((finding.get("severity") or {}).get("level")) or "unknown"
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    record["severity_counts"] = severity_counts
except Exception as exc:
    record["findings_error"] = str(exc)
try:
    coverage = json.loads((outp / "coverage.json").read_text())
    record["coverage"] = coverage.get("completeness")
except Exception as exc:
    record["coverage_error"] = str(exc)
print(json.dumps(record, ensure_ascii=False, sort_keys=True))
PY
)"
  append_summary "$record"

  rm -f "$STATE_DIR/$case_id.running"
  final_state="$(python3 -c 'import json,sys; status=json.loads(sys.argv[1])["status"]; print("accepted" if status == "accepted" else ("partial" if status == "partial_artifacts" else "failed"))' "$record")"
  : >"$STATE_DIR/$case_id.$final_state"
  write_status

  if grep -q "You've hit your usage limit" "$log"; then
    {
      printf 'case_id=%s\n' "$case_id"
      printf 'log=%s\n' "$log"
      grep "You've hit your usage limit" "$log" | tail -n 1
    } >"$QUOTA_SENTINEL"
    return 76
  fi
  if grep -Eq "could not be refreshed|refresh token was already used|refresh token was revoked" "$log"; then
    {
      printf 'case_id=%s\n' "$case_id"
      printf 'log=%s\n' "$log"
      grep -E "could not be refreshed|refresh token was already used|refresh token was revoked" "$log" | tail -n 1
    } >"$AUTH_SENTINEL"
    return 77
  fi

  return 0
}

should_stop_for_case_limit() {
  local started="$1"
  if [[ -z "$MAX_NEW_CASES" ]]; then
    return 1
  fi
  if [[ "$started" -ge "$MAX_NEW_CASES" ]]; then
    printf 'case limit reached: CODEX_SECURITY_MAX_NEW_CASES=%s\n' "$MAX_NEW_CASES" >&2
    return 0
  fi
  return 1
}

case_id_from_row() {
  json_get "$1" case_id
}

# Keep the scheduler's queue on an explicit file descriptor.  Background
# workers are started with stdin redirected to /dev/null, but this descriptor
# also prevents accidental consumption of the queue by any helper launched
# from the parent shell.
read_queue_row() {
  IFS= read -r REPLY <&3
}

case_is_terminal_or_active() {
  local case_id="$1"
  [[ -f "$STATE_DIR/$case_id.accepted" ||
     -f "$STATE_DIR/$case_id.partial" ||
     -f "$STATE_DIR/$case_id.failed" ||
     -f "$STATE_DIR/$case_id.stopped" ||
     -f "$STATE_DIR/$case_id.running" ||
     -f "$STATE_DIR/$case_id.prepared" ]]
}

validate_config() {
  [[ -f "$QUEUE" ]] || fail "queue not found: $QUEUE"
  case "$OUTER_PARALLELISM" in
    ''|*[!0-9]*) fail "invalid CODEX_SECURITY_OUTER_PARALLELISM=$OUTER_PARALLELISM" ;;
  esac
  [[ "$OUTER_PARALLELISM" -ge 1 ]] || \
    fail "invalid CODEX_SECURITY_OUTER_PARALLELISM=$OUTER_PARALLELISM"

  if [[ -n "$MAX_NEW_CASES" ]]; then
    case "$MAX_NEW_CASES" in
      *[!0-9]*) fail "invalid CODEX_SECURITY_MAX_NEW_CASES=$MAX_NEW_CASES" ;;
    esac
  fi

  if [[ "$USE_TRAEX_WRAPPER" == "1" ]]; then
    [[ -n "$WRAPPER" && -x "$WRAPPER" ]] || fail "CODEX_SECURITY_WRAPPER must be executable"
    command -v "$TRAEX_BIN" >/dev/null 2>&1 || fail "traex binary not found: $TRAEX_BIN"
    [[ -z "$PLUGIN_DIR" || -d "$PLUGIN_DIR" ]] || fail "plugin dir not found: $PLUGIN_DIR"
  fi
}

started_cases=0
active_pids=()
abort_status=0

wait_one_worker() {
  local pid status
  [[ "${#active_pids[@]}" -gt 0 ]] || return 0
  pid="${active_pids[0]}"
  active_pids=("${active_pids[@]:1}")
  set +e
  wait "$pid"
  status=$?
  set -e
  if [[ "$status" -eq 76 || "$status" -eq 77 ]]; then
    abort_status="$status"
  fi
}

wait_for_worker_slot() {
  while [[ "${#active_pids[@]}" -ge "$OUTER_PARALLELISM" ]]; do
    wait_one_worker
    if [[ "$abort_status" -ne 0 ]]; then
      return "$abort_status"
    fi
  done
  return 0
}

wait_for_all_workers() {
  while [[ "${#active_pids[@]}" -gt 0 ]]; do
    wait_one_worker
  done
}

on_interrupt() {
  local pid
  for pid in "${active_pids[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  python3 - "$STATE_DIR" <<'PY'
import pathlib
import sys

state_dir = pathlib.Path(sys.argv[1])
for marker in list(state_dir.glob("*.running")) + list(state_dir.glob("*.prepared")):
    case_id, _ = marker.name.rsplit(".", 1)
    marker.unlink(missing_ok=True)
    (state_dir / f"{case_id}.stopped").write_text("runner interrupted\n", encoding="utf-8")
PY
  write_status || true
  exit 130
}

main() {
  acquire_run_lock
  validate_config
  check_quota_guard
  check_auth_guard
  write_status
  if [[ "${CODEX_SECURITY_STATUS_ONLY:-}" == "1" ]]; then
    printf 'status refreshed: %s\n' "$STATUS_TSV"
    exit 0
  fi

  trap on_interrupt INT TERM

  local row case_id
  exec 3<"$QUEUE"
  while read_queue_row; do
    row="$REPLY"
    [[ -n "$row" ]] || continue
    check_quota_guard
    check_auth_guard
    should_stop_for_case_limit "$started_cases" && break
    case_id="$(case_id_from_row "$row")"
    if case_is_terminal_or_active "$case_id"; then
      continue
    fi
    wait_for_worker_slot
    if [[ "$abort_status" -ne 0 ]]; then
      break
    fi
    check_quota_guard
    check_auth_guard
    # A worker inherits this loop's queue file descriptor unless its standard
    # input is detached.  Tools launched by a worker may read stdin, which
    # would otherwise advance the scheduler's queue and silently skip rows.
    run_case "$row" </dev/null &
    active_pids+=("$!")
    started_cases=$((started_cases + 1))
  done
  exec 3<&-

  wait_for_all_workers
  if [[ "$abort_status" -ne 0 ]]; then
    exit "$abort_status"
  fi

  write_status
  printf 'done batch_dir=%s\n' "$BATCH_DIR"
}

main "$@"
