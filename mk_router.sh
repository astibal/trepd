#!/usr/bin/env bash
set -euo pipefail
umask 0077

usage() {
    cat >&2 <<EOF
Usage:
  $0 <id 1..255> <host|user@host> [trepd options...]

Example:
  $0 42 router.example [trepd options...]

Environment:
  TREP_PORT       TCP port (default: 43000 + id)
  TREP_DISTANCE   Imported route metric; passed as --distance when set

Direction:
  --to-peer-*     Local export policy
  --from-peer-*   Remote export policy
  --export-filter Final filter before sending
  --import-filter Final filter before installing
EOF
}

if (( $# < 2 )); then
    usage
    exit 1
fi

id="$1"
remote="$2"
shift 2

if ! [[ "$id" =~ ^[0-9]+$ ]] || (( id < 1 || id > 255 )); then
    echo "Router id must be in range 1..255" >&2
    exit 1
fi

if [[ "$remote" != *@* ]]; then
    remote="root@${remote}"
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source_file="${script_dir}/trepd.cpp"

client_if="ut${id}c"
server_if="ut${id}s"

client_ip="10.254.${id}.1"
server_ip="10.254.${id}.2"

tcp_port="${TREP_PORT:-$((43000 + id))}"

run_dir="/run/tuntom"

local_bin="/tmp/trepd_${id}c"
remote_bin="/tmp/trepd_${id}s"

local_stage="${local_bin}.new.$$"
remote_stage="${remote_bin}.new.$$"

local_pid_file="${run_dir}/trepd_${id}c.pid"
remote_pid_file="${run_dir}/trepd_${id}s.pid"

local_log="/tmp/trepd-${id}-client.log"
remote_log="/tmp/trepd-${id}-server.log"

input_args=( "$@" )
local_router_args=()
remote_router_args=()

for ((i = 0; i < ${#input_args[@]}; i++)); do
    argument="${input_args[i]}"

    case "$argument" in
        --to-peer-filter|--to-peer-route|--to-peer-filter6|--to-peer-route6|--export-filter|--export-filter6|--import-filter|--import-filter6)
            if ((i + 1 >= ${#input_args[@]})); then
                echo "$argument needs value" >&2
                exit 1
            fi
            i=$((i + 1))
            local_router_args+=( "$argument" "${input_args[i]}" )
            ;;
        --to-peer-static|--to-peer-connected|--to-peer-default|--to-peer-static6|--to-peer-connected6|--to-peer-default6)
            local_router_args+=( "$argument" )
            ;;
        --from-peer-route)
            if ((i + 1 >= ${#input_args[@]})); then
                echo "$argument needs value" >&2
                exit 1
            fi
            i=$((i + 1))
            remote_router_args+=( --to-peer-route "${input_args[i]}" )
            ;;
        --from-peer-route6)
            if ((i + 1 >= ${#input_args[@]})); then
                echo "$argument needs value" >&2
                exit 1
            fi
            i=$((i + 1))
            remote_router_args+=( --to-peer-route6 "${input_args[i]}" )
            ;;
        --from-peer-static)
            remote_router_args+=( --to-peer-static )
            ;;
        --from-peer-connected)
            remote_router_args+=( --to-peer-connected )
            ;;
        --from-peer-default)
            remote_router_args+=( --to-peer-default )
            ;;
        --from-peer-static6)
            remote_router_args+=( --to-peer-static6 )
            ;;
        --from-peer-connected6)
            remote_router_args+=( --to-peer-connected6 )
            ;;
        --from-peer-default6)
            remote_router_args+=( --to-peer-default6 )
            ;;
        --from-peer-filter|--from-peer-filter6)
            echo "$argument is not supported; use --import-filter" >&2
            exit 1
            ;;
        --export-*|--import-*)
            echo "Unknown directional option: $argument" >&2
            exit 1
            ;;
        *)
            local_router_args+=( "$argument" )
            remote_router_args+=( "$argument" )
            ;;
    esac
done

if [[ -n "${TREP_DISTANCE:-}" ]]; then
    local_router_args+=( --distance "$TREP_DISTANCE" )
    remote_router_args+=( --distance "$TREP_DISTANCE" )
fi

local_router_args+=( --port "$tcp_port" )
remote_router_args+=( --port "$tcp_port" )

if [[ ! -f "$source_file" ]]; then
    echo "Missing source file: $source_file" >&2
    exit 1
fi

if [[ $EUID -eq 0 ]]; then
    root_cmd=()
else
    root_cmd=(sudo -E)
fi

ensure_route_protocol_name() {
    local rt_protos="/etc/iproute2/rt_protos"

    if ! "${root_cmd[@]}" grep -Eq "^[[:space:]]*100[[:space:]]+trepd([[:space:]]|$)" "$rt_protos" 2>/dev/null; then
        if "${root_cmd[@]}" grep -Eq "^[[:space:]]*100([[:space:]]|$)" "$rt_protos" 2>/dev/null; then
            echo "Route protocol 100 is already assigned to another name" >&2
            exit 1
        fi

        "${root_cmd[@]}" sh -c '
            mkdir -p /etc/iproute2
            printf "%s\n" "100 trepd" >>/etc/iproute2/rt_protos
        '
    fi

    ssh "$remote" '
        set -e
        rt_protos="/etc/iproute2/rt_protos"

        if grep -Eq "^[[:space:]]*100[[:space:]]+trepd([[:space:]]|$)" "$rt_protos" 2>/dev/null; then
            exit 0
        fi

        if grep -Eq "^[[:space:]]*100([[:space:]]|$)" "$rt_protos" 2>/dev/null; then
            echo "Route protocol 100 is already assigned to another name" >&2
            exit 1
        fi

        mkdir -p /etc/iproute2
        printf "%s\n" "100 trepd" >>"$rt_protos"
    '
}

ensure_route_protocol_name

mk_lock_file="${run_dir}/mk_router_${id}.lock"

acquire_mk_lock() {
    "${root_cmd[@]}" mkdir -p "$run_dir"

    coproc TREP_MK_LOCK {
        "${root_cmd[@]}" bash -c '
            lock_file="$1"

            exec 9>"$lock_file"

            if ! flock -n 9; then
                exit 75
            fi

            printf "LOCKED\n"
            cat >/dev/null
        ' bash "$mk_lock_file"
    }

    local lock_status=""
    local lock_rc=0

    if ! IFS= read -r lock_status <&"${TREP_MK_LOCK[0]}"; then
        wait "$TREP_MK_LOCK_PID" || lock_rc=$?

        if (( lock_rc == 75 )); then
            echo "Another mk_router process is already operating on id ${id}" >&2
            echo "Lock: ${mk_lock_file}" >&2
        else
            echo "Unable to acquire mk_router lock ${mk_lock_file}" >&2
        fi

        exit 1
    fi

    if [[ "$lock_status" != "LOCKED" ]]; then
        echo "Unable to acquire mk_router lock ${mk_lock_file}" >&2
        exit 1
    fi

    echo "  mk_ lock:   ${mk_lock_file}"
}

stage_active=1

cleanup_staging() {
    if (( stage_active )); then
        rm -f "$local_stage" 2>/dev/null || true
        ssh "$remote" "rm -f '$remote_stage'" >/dev/null 2>&1 || true
    fi
}

trap cleanup_staging EXIT

shell_quote() {
    printf "%q" "$1"
}

make_remote_args() {
    local output=""
    local arg

    for arg in "$@"; do
        output+=" $(shell_quote "$arg")"
    done

    printf "%s" "$output"
}

stop_local_process() {
    if [[ ! -f "$local_pid_file" ]]; then
        return
    fi

    local pid
    pid="$(cat "$local_pid_file" 2>/dev/null || true)"

    if [[ "$pid" =~ ^[0-9]+$ ]]; then
        local argv0

        argv0="$(
            "${root_cmd[@]}" sh -c \
                "tr '\0' '\n' < '/proc/${pid}/cmdline' 2>/dev/null | head -n 1" \
                || true
        )"

        if [[ "$argv0" == "$local_bin" ]]; then
            "${root_cmd[@]}" kill "$pid" 2>/dev/null || true

            for _ in $(seq 1 20); do
                if ! "${root_cmd[@]}" kill -0 "$pid" 2>/dev/null; then
                    break
                fi
                sleep 0.05
            done

            if "${root_cmd[@]}" kill -0 "$pid" 2>/dev/null; then
                "${root_cmd[@]}" kill -KILL "$pid" 2>/dev/null || true
            fi
        else
            echo "WARNING: stale local PID file ${local_pid_file}: PID ${pid} is not ${local_bin}" >&2
        fi
    fi

    "${root_cmd[@]}" rm -f "$local_pid_file"
}

stop_remote_process() {
    ssh "$remote" "
        if [ -f '$remote_pid_file' ]; then
            pid=\$(cat '$remote_pid_file' 2>/dev/null || true)

            case \"\$pid\" in
                ''|*[!0-9]*)
                    ;;
                *)
                    argv0=\$(tr '\000' '\n' < \"/proc/\$pid/cmdline\" 2>/dev/null | head -n 1 || true)

                    if [ \"\$argv0\" = '$remote_bin' ]; then
                        kill \"\$pid\" 2>/dev/null || true

                        n=0
                        while kill -0 \"\$pid\" 2>/dev/null && [ \"\$n\" -lt 20 ]; do
                            sleep 0.05
                            n=\$((n + 1))
                        done

                        if kill -0 \"\$pid\" 2>/dev/null; then
                            kill -KILL \"\$pid\" 2>/dev/null || true
                        fi
                    else
                        echo \"WARNING: stale remote PID file ${remote_pid_file}: PID \$pid is not ${remote_bin}\" >&2
                    fi
                    ;;
            esac

            rm -f '$remote_pid_file'
        fi
    "
}

prepare_runtime_dirs() {
    "${root_cmd[@]}" mkdir -p "$run_dir"
    ssh "$remote" "mkdir -p '$run_dir'"
}

build_local_stage() {
    echo "  build local:  ${local_stage}"

    g++ \
        -std=c++17 \
        -O2 \
        -Wall \
        -Wextra \
        -Wpedantic \
        "$source_file" \
        -o "$local_stage"

    chmod 0700 "$local_stage"
}

build_remote_stage() {
    local remote_source="/tmp/trepd-${id}.cpp"

    echo "  copy source:  ${remote}:${remote_source}"

    scp -q \
        "$source_file" \
        "${remote}:${remote_source}"

    echo "  build remote: ${remote_stage}"

    ssh "$remote" "
        set -e

        g++ \
            -std=c++17 \
            -O2 \
            -Wall \
            -Wextra \
            -Wpedantic \
            '$remote_source' \
            -o '$remote_stage'

        chmod 0700 '$remote_stage'
        rm -f '$remote_source'
    "
}

install_staged_binaries() {
    echo "  install local:  ${local_bin}"
    "${root_cmd[@]}" mv -f "$local_stage" "$local_bin"

    echo "  install remote: ${remote_bin}"
    ssh "$remote" "mv -f '$remote_stage' '$remote_bin'"

    stage_active=0
}

start_local_process() {
    echo "  start local:  ${client_if} ${client_ip} -> ${server_ip}"

    "${root_cmd[@]}" sh -c '
        run_dir="$1"
        pid_file="$2"
        log_file="$3"
        binary="$4"
        interface="$5"
        local_ip="$6"
        peer_ip="$7"
        shift 7

        mkdir -p "$run_dir"

        nohup \
            "$binary" \
            "$interface" \
            "$local_ip" \
            "$peer_ip" \
            "$@" \
            >"$log_file" 2>&1 &

        pid=$!
        printf "%s\n" "$pid" >"$pid_file"
    ' sh \
        "$run_dir" \
        "$local_pid_file" \
        "$local_log" \
        "$local_bin" \
        "$client_if" \
        "$client_ip" \
        "$server_ip" \
        "${local_router_args[@]}"
}

start_remote_process() {
    local quoted_args
    quoted_args="$(make_remote_args "${remote_router_args[@]}")"

    echo "  start remote: ${server_if} ${server_ip} -> ${client_ip}"

    ssh "$remote" "
        set -e
        mkdir -p '$run_dir'

        nohup \
            '$remote_bin' \
            '$server_if' \
            '$server_ip' \
            '$client_ip' \
            ${quoted_args} \
            >'$remote_log' 2>&1 &

        pid=\$!
        printf '%s\n' \"\$pid\" >'$remote_pid_file'
    "
}

verify_local_process() {
    local pid
    pid="$(cat "$local_pid_file" 2>/dev/null || true)"

    if ! [[ "$pid" =~ ^[0-9]+$ ]]; then
        echo "Local trepd did not create a valid PID file" >&2
        return 1
    fi

    sleep 0.15

    if ! "${root_cmd[@]}" kill -0 "$pid" 2>/dev/null; then
        echo "Local trepd failed to stay running" >&2
        echo "Log: $local_log" >&2
        tail -n 30 "$local_log" 2>/dev/null || true
        return 1
    fi
}

verify_remote_process() {
    if ! ssh "$remote" "
        pid=\$(cat '$remote_pid_file' 2>/dev/null || true)

        case \"\$pid\" in
            ''|*[!0-9]*)
                exit 1
                ;;
        esac

        sleep 0.15
        kill -0 \"\$pid\" 2>/dev/null
    "; then
        echo "Remote trepd failed to stay running" >&2
        echo "Remote log: ${remote}:${remote_log}" >&2

        ssh "$remote" "tail -n 30 '$remote_log' 2>/dev/null || true" >&2 || true
        return 1
    fi
}

acquire_mk_lock

echo "TREP router ${id}"
echo "  remote:     ${remote}"
echo "  interfaces: ${client_if} <-> ${server_if}"
echo "  addresses:  ${client_ip} <-> ${server_ip}"
echo "  TCP port:   ${tcp_port}"

prepare_runtime_dirs

# Compile first. Running router is untouched if either build fails.
build_local_stage
build_remote_stage

echo "Stopping old router..."
stop_local_process
stop_remote_process

# Staged binaries become active only after both builds succeeded.
install_staged_binaries

echo "Starting router..."

# The lower IP is the TREP listener, so start it first.
start_local_process
verify_local_process

start_remote_process
verify_remote_process

echo
echo "TREP router ${id} is up."
echo "  local log:  ${local_log}"
echo "  remote log: ${remote}:${remote_log}"
echo "  local pid:  ${local_pid_file}"
echo "  remote pid: ${remote}:${remote_pid_file}"
