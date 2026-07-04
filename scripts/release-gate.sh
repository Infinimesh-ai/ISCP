#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
. "${script_dir}/common.sh"

cd "${ISCP_REPO_ROOT}"

dist_dir="${ISCP_REPO_ROOT}/dist"
summary_path="${dist_dir}/release-gate-summary.json"
compose_file="${ISCP_REPO_ROOT}/deploy/docker-compose/docker-compose.yaml"
mkdir -p "${dist_dir}"

json_string() {
    local value="${1-}"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//$'\n'/\\n}"
    value="${value//$'\r'/\\r}"
    value="${value//$'\t'/\\t}"
    printf '"%s"' "${value}"
}

duration_now_ms() {
    date +%s%3N
}

host_probe_address() {
    local bind_address="$1"
    case "${bind_address}" in
        0.0.0.0|::|'[::]') printf '127.0.0.1\n' ;;
        *) printf '%s\n' "${bind_address}" ;;
    esac
}

tcp_port_available() {
    local address="$1"
    local port="$2"
    if timeout 1 bash -c ":</dev/tcp/${address}/${port}" >/dev/null 2>&1; then
        return 1
    fi
    return 0
}

free_tcp_port() {
    local address="$1"
    local port
    for _ in $(seq 1 100); do
        port="$(shuf -i 20000-65000 -n 1)"
        if tcp_port_available "${address}" "${port}"; then
            printf '%s\n' "${port}"
            return
        fi
    done
    printf 'could not find a free TCP port on %s\n' "${address}" >&2
    return 1
}

resolve_compose_port() {
    local env_name="$1"
    local default_port="$2"
    local bind_address="$3"
    local configured="${!env_name-}"
    if [[ -n "${configured}" ]]; then
        printf '%s\n' "${configured}"
        return
    fi
    _="${default_port}"
    free_tcp_port "${bind_address}"
}

docker_compose() {
    if ! command -v docker >/dev/null 2>&1; then
        printf 'Docker is required for release gate Compose service validation.\n' >&2
        return 1
    fi
    if [[ ! -f "${compose_file}" ]]; then
        printf 'Compose file is missing: %s\n' "${compose_file}" >&2
        return 1
    fi
    docker compose -f "${compose_file}" "$@"
}

ensure_compose_mount_permissions() {
    chmod a+rx "${ISCP_REPO_ROOT}/deploy" \
        "${ISCP_REPO_ROOT}/deploy/migrations" \
        "${ISCP_REPO_ROOT}/deploy/migrations/postgres"
    chmod a+r "${ISCP_REPO_ROOT}"/deploy/migrations/postgres/*.sql
}

http_ready() {
    local uri="$1"
    if command -v curl >/dev/null 2>&1; then
        curl -fsS --max-time 3 "${uri}" >/dev/null
        return
    fi
    if command -v wget >/dev/null 2>&1; then
        wget -q -T 3 -O /dev/null "${uri}"
        return
    fi
    printf 'curl or wget is required for HTTP readiness checks.\n' >&2
    return 1
}

wait_http_ready() {
    local name="$1"
    local endpoint="$2"
    local timeout_seconds="${3:-180}"
    local deadline=$((SECONDS + timeout_seconds))
    local last_error=''

    while (( SECONDS < deadline )); do
        local ok=1
        for path in /healthz /version; do
            if ! http_ready "${endpoint}${path}" >/tmp/iscp-http-ready.log 2>&1; then
                last_error="$(cat /tmp/iscp-http-ready.log 2>/dev/null || true)"
                ok=0
                break
            fi
        done
        if [[ "${ok}" -eq 1 ]]; then
            return
        fi
        sleep 2
    done

    printf '%s did not become ready at %s within %s seconds. Last error: %s\n' \
        "${name}" "${endpoint}" "${timeout_seconds}" "${last_error}" >&2
    return 1
}

compose_details_json=''
start_compose_services() {
    local bind_address="${ISCP_BIND_ADDR:-127.0.0.1}"
    local probe_address
    probe_address="$(host_probe_address "${bind_address}")"
    local relay_port
    relay_port="$(resolve_compose_port ISCP_RELAY_PORT 8080 "${probe_address}")" || return
    local trust_port
    trust_port="$(resolve_compose_port ISCP_TRUST_PORT 8081 "${probe_address}")" || return
    local postgres_port
    postgres_port="$(resolve_compose_port ISCP_POSTGRES_PORT 5432 "${probe_address}")" || return

    export ISCP_BIND_ADDR="${bind_address}"
    export ISCP_RELAY_PORT="${relay_port}"
    export ISCP_TRUST_PORT="${trust_port}"
    export ISCP_POSTGRES_PORT="${postgres_port}"

    ensure_compose_mount_permissions
    docker_compose up --build --detach postgres relay trust-root || return

    local relay_probe_endpoint="http://${probe_address}:${relay_port}"
    local trust_probe_endpoint="http://${probe_address}:${trust_port}"
    wait_http_ready "Relay Reference Service" "${relay_probe_endpoint}" || return
    wait_http_ready "Trust Root Reference Service" "${trust_probe_endpoint}" || return

    local go_execution
    go_execution="$(go_execution_mode)" || return
    local runner_address="${probe_address}"
    if [[ "${go_execution}" == "docker-fallback" && "$(uname -s)" != "Linux" ]]; then
        runner_address="host.docker.internal"
    fi

    export ISCP_RELAY_ENDPOINT="http://${runner_address}:${relay_port}"
    export ISCP_TRUST_ENDPOINT="http://${runner_address}:${trust_port}"

    compose_details_json="$(printf '{"compose_file":"deploy/docker-compose/docker-compose.yaml","services":["postgres","relay","trust-root"],"bind_address":%s,"postgres_port":%s,"host_probe":{"relay_endpoint":%s,"trust_endpoint":%s},"conformance":{"go_execution":%s,"relay_endpoint":%s,"trust_endpoint":%s}}' \
        "$(json_string "${bind_address}")" \
        "$(json_string "${postgres_port}")" \
        "$(json_string "${relay_probe_endpoint}")" \
        "$(json_string "${trust_probe_endpoint}")" \
        "$(json_string "${go_execution}")" \
        "$(json_string "${ISCP_RELAY_ENDPOINT}")" \
        "$(json_string "${ISCP_TRUST_ENDPOINT}")")"
}

gate_results=()
failed=0

append_gate_result() {
    local name="$1"
    local command="$2"
    local started_at="$3"
    local duration_ms="$4"
    local status="$5"
    local error="$6"
    local details="${7:-null}"
    local error_json='null'
    if [[ -n "${error}" ]]; then
        error_json="$(json_string "${error}")"
    fi
    gate_results+=("$(printf '{"name":%s,"command":%s,"started_at":%s,"status":%s,"duration_ms":%s,"error":%s,"details":%s}' \
        "$(json_string "${name}")" \
        "$(json_string "${command}")" \
        "$(json_string "${started_at}")" \
        "$(json_string "${status}")" \
        "${duration_ms}" \
        "${error_json}" \
        "${details}")")
}

run_gate() {
    local name="$1"
    local command_label="$2"
    shift 2

    local started_at
    started_at="$(utc_now)"
    local started_ms
    started_ms="$(duration_now_ms)"

    set +e
    "$@"
    local exit_code=$?
    set -e

    local ended_ms
    ended_ms="$(duration_now_ms)"
    local duration_ms=$((ended_ms - started_ms))

    if [[ "${exit_code}" -eq 0 ]]; then
        append_gate_result "${name}" "${command_label}" "${started_at}" "${duration_ms}" "pass" "" "null"
        return 0
    fi

    append_gate_result "${name}" "${command_label}" "${started_at}" "${duration_ms}" "fail" "${command_label} failed with exit code ${exit_code}" "null"
    failed=1
    return 1
}

run_compose_gate() {
    local started_at
    started_at="$(utc_now)"
    local started_ms
    started_ms="$(duration_now_ms)"

    set +e
    start_compose_services
    local exit_code=$?
    set -e

    local ended_ms
    ended_ms="$(duration_now_ms)"
    local duration_ms=$((ended_ms - started_ms))

    if [[ "${exit_code}" -eq 0 ]]; then
        append_gate_result "compose-services" "docker compose" "${started_at}" "${duration_ms}" "pass" "" "${compose_details_json}"
        return 0
    fi

    append_gate_result "compose-services" "docker compose" "${started_at}" "${duration_ms}" "fail" "docker compose failed with exit code ${exit_code}" "null"
    failed=1
    return 1
}

write_summary() {
    local decision="go"
    if [[ "${failed}" -ne 0 ]]; then
        decision="no-go"
    fi
    local gates_json
    gates_json="$(IFS=,; printf '%s' "${gate_results[*]}")"
    printf '{"type":"iscp.release_gate.summary.v2","generated_at":%s,"release_decision":%s,"gates":[%s]}\n' \
        "$(json_string "$(utc_now)")" \
        "$(json_string "${decision}")" \
        "${gates_json}" > "${summary_path}"
}

run_compose_gate || true
if [[ "${failed}" -eq 0 ]]; then run_gate "test" "./scripts/test.sh" ./scripts/test.sh || true; fi
if [[ "${failed}" -eq 0 ]]; then run_gate "conformance" "./scripts/conformance.sh" ./scripts/conformance.sh || true; fi
if [[ "${failed}" -eq 0 ]]; then run_gate "secret-scan" "./scripts/secret-scan.sh" ./scripts/secret-scan.sh || true; fi
if [[ "${failed}" -eq 0 ]]; then run_gate "govulncheck" "./scripts/govulncheck.sh" ./scripts/govulncheck.sh || true; fi
if [[ "${failed}" -eq 0 ]]; then run_gate "gosec" "./scripts/gosec.sh" ./scripts/gosec.sh || true; fi
if [[ "${failed}" -eq 0 ]]; then run_gate "generate-openapi" "./scripts/generate-openapi.sh" ./scripts/generate-openapi.sh || true; fi
if [[ "${failed}" -eq 0 ]]; then run_gate "generate-schemas" "./scripts/generate-schemas.sh" ./scripts/generate-schemas.sh || true; fi
if [[ "${failed}" -eq 0 ]]; then run_gate "traceability" "./scripts/traceability.sh" ./scripts/traceability.sh || true; fi
if [[ "${failed}" -eq 0 ]]; then run_gate "sbom" "./scripts/sbom.sh" ./scripts/sbom.sh || true; fi
if [[ "${failed}" -eq 0 ]]; then run_gate "conformance-release-validation" "go" invoke_go run ./tools/iscp-cli/cmd/iscp conformance validate-report --release --output conformance/report.json || true; fi

write_summary

if [[ "${failed}" -ne 0 ]]; then
    printf 'release gate failed; see %s\n' "${summary_path}" >&2
    exit 1
fi

printf 'release gate passed; see %s\n' "${summary_path}"
