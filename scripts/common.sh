#!/usr/bin/env bash

set -euo pipefail

ISCP_SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ISCP_REPO_ROOT="$(cd -- "${ISCP_SCRIPT_DIR}/.." && pwd)"

go_execution_mode() {
    if command -v go >/dev/null 2>&1; then
        printf 'local-go\n'
        return
    fi
    printf 'docker-fallback\n'
}

invoke_go() {
    if command -v go >/dev/null 2>&1; then
        go "$@"
        return
    fi

    if ! command -v docker >/dev/null 2>&1; then
        printf 'Go 1.25.x is not installed and Docker is not available for fallback execution.\n' >&2
        return 127
    fi

    docker_args=(run --rm)
    if [[ "$(uname -s)" == "Linux" ]]; then
        docker_args+=(--network host --add-host=host.docker.internal:host-gateway)
    fi

    docker "${docker_args[@]}" \
        --user "$(id -u):$(id -g)" \
        -e HOME=/tmp/iscp-go \
        -e GOPATH=/tmp/iscp-go \
        -e GOCACHE=/tmp/iscp-go/cache \
        -e GOMODCACHE=/tmp/iscp-go/pkg/mod \
        -e ISCP_PROFILE \
        -e ISCP_RELAY_ENDPOINT \
        -e ISCP_TRUST_ENDPOINT \
        -e ISCP_BIND_ADDR \
        -e ISCP_RELAY_PORT \
        -e ISCP_TRUST_PORT \
        -e ISCP_POSTGRES_PORT \
        -v "${ISCP_REPO_ROOT}:/workspace" \
        -w /workspace \
        golang:1.25 \
        go "$@"
}

utc_now() {
    date -u +"%Y-%m-%dT%H:%M:%SZ"
}
