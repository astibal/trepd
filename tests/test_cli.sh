#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
binary="$(mktemp)"
trap 'rm -f "$binary"' EXIT

g++ \
    -std=c++17 \
    -O2 \
    -Wall \
    -Wextra \
    -Wpedantic \
    "$project_dir/trepd.cpp" \
    -o "$binary"

expect_rejected() {
    local description="$1"
    shift
    local output

    output="$(
        "$binary" trepd-test-missing 127.0.0.1 127.0.0.2 "$@" 2>&1 \
            || true
    )"

    if [[ "$output" != *"bad "* ]]; then
        echo "FAIL: ${description}" >&2
        echo "Output: ${output}" >&2
        return 1
    fi
}

expect_rejected "port with trailing characters" --port 42oops
expect_rejected "negative port" --port -1
expect_rejected "overflowing distance" --distance 4294967296
expect_rejected "IPv4 prefix length with trailing characters" \
    --to-peer-route 192.0.2.0/24oops
expect_rejected "IPv6 prefix length with trailing characters" \
    --to-peer-route6 2001:db8::/64oops

echo "CLI tests passed"
