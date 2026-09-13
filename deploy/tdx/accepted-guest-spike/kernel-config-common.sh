#!/usr/bin/env bash

refuse_duplicate_kernel_config_symbols() {
  local config=$1
  awk '
    /^CONFIG_[A-Z0-9_]+=/ { symbol=$0; sub(/=.*/, "", symbol) }
    /^# CONFIG_[A-Z0-9_]+ is not set$/ { symbol=$2 }
    !(/^CONFIG_[A-Z0-9_]+=/ || /^# CONFIG_[A-Z0-9_]+ is not set$/) { next }
    seen[symbol]++ { printf "duplicate kernel config symbol: %s\n", symbol > "/dev/stderr"; failed=1 }
    END { exit failed }
  ' "$config"
}
