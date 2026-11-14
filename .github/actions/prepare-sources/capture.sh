#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Source after set -euo; pass a fixed log stem as $1.

# Waits for a tee started through process substitution. Bash 3.2 (macOS /bin/bash)
# does not report such a process as a child: `wait` then returns 127, so poll until
# it exits instead (bounded to 10 s).
capture_wait() {
  local pid=$1 rc=0 tries=0
  wait "$pid" 2>/dev/null || rc=$?
  if ((rc == 127)); then
    while kill -0 "$pid" 2>/dev/null && ((tries < 100)); do
      sleep 0.1
      tries=$((tries + 1))
    done
    rc=0
  fi
  return "$rc"
}

capture_setup() {
  local stem=$1
  local log_dir="target/native-graph-preparation-logs"
  mkdir -p "$log_dir"
  stdout_log="${log_dir}/${stem}.stdout.log"
  stderr_log="${log_dir}/${stem}.stderr.log"
  status_log="${log_dir}/${stem}.status"

  exec 3>&1 4>&2
  exec > >(tee "$stdout_log" >&3)
  stdout_pid=$!
  exec 2> >(tee "$stderr_log" >&4)
  stderr_pid=$!

  capture_finish() {
    status=$?
    trap - EXIT
    exec 1>&3 2>&4
    tee_status=0
    capture_wait "$stdout_pid" || tee_status=$?
    capture_wait "$stderr_pid" || tee_status=$?
    printf '%s\n' "$status" > "$status_log"
    if ((status == 0 && tee_status != 0)); then
      status=$tee_status
    fi
    exit "$status"
  }
  trap capture_finish EXIT
}

capture_setup "$1"
