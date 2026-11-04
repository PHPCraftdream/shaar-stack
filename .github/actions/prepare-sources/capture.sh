#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Source after set -euo; pass a fixed log stem as $1.

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
    wait "$stdout_pid" || tee_status=$?
    wait "$stderr_pid" || tee_status=$?
    printf '%s\n' "$status" > "$status_log"
    if ((status == 0 && tee_status != 0)); then
      status=$tee_status
    fi
    exit "$status"
  }
  trap capture_finish EXIT
}

capture_setup "$1"
