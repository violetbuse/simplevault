#!/usr/bin/env bash
set -eu

BINARY="/app/simplevault"
RUNTIME_USER="${SIMPLEVAULT_RUNTIME_USER:-simplevault}"
RUNTIME_GROUP="${SIMPLEVAULT_RUNTIME_GROUP:-simplevault}"
RUNTIME_UID="${SIMPLEVAULT_RUNTIME_UID:-10001}"
RUNTIME_GID="${SIMPLEVAULT_RUNTIME_GID:-10001}"
MINIMAL_PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
STAGING_ROOT="${SIMPLEVAULT_STAGING_ROOT:-/tmp}"
STAGED_CONFIG_DIR=""
STAGED_CONFIG_PATH=""
LISTEN_PORT=""

fail() {
    echo "entrypoint: $*" >&2
    exit 1
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

create_runtime_user() {
    if ! getent group "$RUNTIME_GROUP" >/dev/null 2>&1; then
        groupadd --system --gid "$RUNTIME_GID" "$RUNTIME_GROUP"
    fi

    if ! id -u "$RUNTIME_USER" >/dev/null 2>&1; then
        useradd \
            --system \
            --uid "$RUNTIME_UID" \
            --gid "$RUNTIME_GROUP" \
            --no-create-home \
            --home-dir /nonexistent \
            --shell /usr/sbin/nologin \
            "$RUNTIME_USER"
    fi
}

harden_binary() {
    chown root:root "$BINARY"
    chmod 0111 "$BINARY"
    chmod 0711 /app
    setfacl -bn "$BINARY"
}

runtime_uid() {
    id -u "$RUNTIME_USER"
}

runtime_gid() {
    id -g "$RUNTIME_USER"
}

parse_args() {
    CONFIG_MODE=""
    CONFIG_PATH=""
    CONFIG_ENV_NAME=""
    PORT_OVERRIDE=""
    EXPECT=""

    for arg in "$@"; do
        if [ -n "$EXPECT" ]; then
            case "$EXPECT" in
                config_env)
                    CONFIG_MODE="env"
                    CONFIG_ENV_NAME="$arg"
                    ;;
                port)
                    PORT_OVERRIDE="$arg"
                    ;;
            esac
            EXPECT=""
            continue
        fi

        case "$arg" in
            --config-env)
                EXPECT="config_env"
                ;;
            --config-env=*)
                CONFIG_MODE="env"
                CONFIG_ENV_NAME="${arg#*=}"
                ;;
            --port|-p)
                EXPECT="port"
                ;;
            --port=*|-p=*)
                PORT_OVERRIDE="${arg#*=}"
                ;;
            --*)
                ;;
            -*)
                ;;
            *)
                if [ -z "$CONFIG_MODE" ]; then
                    CONFIG_MODE="file"
                    CONFIG_PATH="$arg"
                fi
                ;;
        esac
    done

    [ -z "$EXPECT" ] || fail "missing value for option requiring an argument"
    [ -n "$CONFIG_MODE" ] || fail "expected either a config path or --config-env"
}

parse_port_from_json() {
    jq -er '.server_port | if type == "number" then . else error("server_port must be numeric") end'
}

resolve_listen_port_from_env() {
    [ -n "$CONFIG_ENV_NAME" ] || fail "--config-env requires an environment variable name"
    CONFIG_ENV_VALUE="$(printenv "$CONFIG_ENV_NAME" || true)"
    [ -n "$CONFIG_ENV_VALUE" ] || fail "environment variable '$CONFIG_ENV_NAME' is not set"

    if printf '%s' "$CONFIG_ENV_VALUE" | jq -e . >/dev/null 2>&1; then
        LISTEN_PORT="$(printf '%s' "$CONFIG_ENV_VALUE" | parse_port_from_json)"
        return
    fi

    decoded="$(printf '%s' "$CONFIG_ENV_VALUE" | base64 -d 2>/dev/null || true)"
    [ -n "$decoded" ] || fail "environment variable '$CONFIG_ENV_NAME' is neither JSON nor base64-encoded JSON"
    LISTEN_PORT="$(printf '%s' "$decoded" | parse_port_from_json)"
}

grant_file_acl() {
    ORIGINAL_CONFIG_PATH="$(readlink -f "$CONFIG_PATH")"
    [ -f "$ORIGINAL_CONFIG_PATH" ] || fail "config file '$ORIGINAL_CONFIG_PATH' does not exist"

    STAGED_CONFIG_DIR="$(mktemp -d "${STAGING_ROOT%/}/simplevault-config.XXXXXX")"
    STAGED_CONFIG_PATH="$STAGED_CONFIG_DIR/config.json"

    cp "$ORIGINAL_CONFIG_PATH" "$STAGED_CONFIG_PATH"
    chmod 0700 "$STAGED_CONFIG_DIR"
    chmod 0600 "$STAGED_CONFIG_PATH"
    chown root:root "$STAGED_CONFIG_DIR" "$STAGED_CONFIG_PATH"
    setfacl -bn "$STAGED_CONFIG_DIR" "$STAGED_CONFIG_PATH"
    setfacl -m "u:${RUNTIME_USER}:rwx" "$STAGED_CONFIG_DIR"
    setfacl -m "u:${RUNTIME_USER}:rw-" "$STAGED_CONFIG_PATH"

    rm -f "$ORIGINAL_CONFIG_PATH" 2>/dev/null || true
}

drop_privs_and_start_file() {
    env -i \
        PATH="$MINIMAL_PATH" \
        HOME=/nonexistent \
        USER="$RUNTIME_USER" \
        LOGNAME="$RUNTIME_USER" \
        setpriv \
        --reuid "$(runtime_uid)" \
        --regid "$(runtime_gid)" \
        --clear-groups \
        --no-new-privs \
        -- "$BINARY" "$@" &
    CHILD_PID=$!
}

drop_privs_and_start_env() {
    env -i \
        PATH="$MINIMAL_PATH" \
        HOME=/nonexistent \
        USER="$RUNTIME_USER" \
        LOGNAME="$RUNTIME_USER" \
        "$CONFIG_ENV_NAME=$CONFIG_ENV_VALUE" \
        setpriv \
        --reuid "$(runtime_uid)" \
        --regid "$(runtime_gid)" \
        --clear-groups \
        --no-new-privs \
        -- "$BINARY" "$@" &
    CHILD_PID=$!

    unset "$CONFIG_ENV_NAME" || true
    CONFIG_ENV_VALUE=""
    unset CONFIG_ENV_VALUE
}

forward_signal() {
    signal="$1"
    if [ -n "${CHILD_PID:-}" ] && kill -0 "$CHILD_PID" 2>/dev/null; then
        kill -s "$signal" "$CHILD_PID" 2>/dev/null || true
    fi
}

wait_for_listen() {
    while kill -0 "$CHILD_PID" 2>/dev/null; do
        if nc -z 127.0.0.1 "$LISTEN_PORT" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.2
    done
    return 1
}

cleanup_staged_config_dir() {
    [ -n "$STAGED_CONFIG_DIR" ] || return 0
    [ -d "$STAGED_CONFIG_DIR" ] || return 0

    setfacl -bn "$STAGED_CONFIG_DIR" 2>/dev/null || true
    if [ -n "$STAGED_CONFIG_PATH" ] && [ -e "$STAGED_CONFIG_PATH" ]; then
        setfacl -bn "$STAGED_CONFIG_PATH" 2>/dev/null || true
    fi
    rmdir "$STAGED_CONFIG_DIR" 2>/dev/null || chmod 000 "$STAGED_CONFIG_DIR" 2>/dev/null || true
}

resolve_listen_port_from_file() {
    LISTEN_PORT="$(
        jq -er '.server_port | if type == "number" then . else error("server_port must be numeric") end' \
            "$STAGED_CONFIG_PATH"
    )"
}

build_file_passthrough_args() {
    PASSTHROUGH_ARGS=()
    EXPECT_FILE_ARG_VALUE=0

    for arg in "$@"; do
        case "$arg" in
            --keep-config|-k)
                ;;
            --config-env|--port|-p)
                PASSTHROUGH_ARGS+=("$arg")
                EXPECT_FILE_ARG_VALUE=1
                ;;
            --config-env=*|--port=*|-p=*)
                PASSTHROUGH_ARGS+=("$arg")
                ;;
            --*)
                PASSTHROUGH_ARGS+=("$arg")
                ;;
            -*)
                PASSTHROUGH_ARGS+=("$arg")
                ;;
            *)
                if [ "${EXPECT_FILE_ARG_VALUE:-0}" -eq 1 ]; then
                    PASSTHROUGH_ARGS+=("$arg")
                    EXPECT_FILE_ARG_VALUE=0
                elif [ "$arg" = "$CONFIG_PATH" ]; then
                    :
                else
                    PASSTHROUGH_ARGS+=("$arg")
                fi
                ;;
        esac
    done

    PASSTHROUGH_ARGS=("$STAGED_CONFIG_PATH" "${PASSTHROUGH_ARGS[@]}")
}

main() {
    command_exists jq || fail "jq is required"
    command_exists setfacl || fail "setfacl is required"
    command_exists setpriv || fail "setpriv is required"
    command_exists nc || fail "nc is required"
    [ -x "$BINARY" ] || fail "binary '$BINARY' is missing"

    parse_args "$@"
    create_runtime_user
    harden_binary

    if [ "$CONFIG_MODE" = "file" ]; then
        grant_file_acl
        if [ -n "$PORT_OVERRIDE" ]; then
            LISTEN_PORT="$PORT_OVERRIDE"
        else
            resolve_listen_port_from_file
        fi
        build_file_passthrough_args "$@"
        drop_privs_and_start_file "${PASSTHROUGH_ARGS[@]}"
    else
        if [ -n "$PORT_OVERRIDE" ]; then
            LISTEN_PORT="$PORT_OVERRIDE"
        else
            resolve_listen_port_from_env
        fi
        drop_privs_and_start_env "$@"
    fi

    trap 'forward_signal TERM' TERM
    trap 'forward_signal INT' INT
    trap 'forward_signal HUP' HUP
    trap 'forward_signal QUIT' QUIT

    if wait_for_listen; then
        if [ "$CONFIG_MODE" = "file" ]; then
            cleanup_staged_config_dir
        fi
    fi

    set +e
    wait "$CHILD_PID"
    EXIT_STATUS=$?
    set -e

    if [ "$CONFIG_MODE" = "file" ]; then
        cleanup_staged_config_dir
    fi

    exit "$EXIT_STATUS"
}

main "$@"
