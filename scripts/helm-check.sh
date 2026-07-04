#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
. "${script_dir}/common.sh"

cd "${ISCP_REPO_ROOT}"
if command -v helm >/dev/null 2>&1; then
    helm template iscp deploy/helm/iscp >/dev/null
    helm template iscp deploy/helm/iscp \
        --set profile=production \
        --set admin.existingSecret=iscp-admin \
        --set postgres.existingSecret=iscp-postgres \
        --set 'relay.allowedOrigins[0]=https://console.example' \
        --set relay.baseURL=https://relay.example \
        --set relay.webSocketURL=wss://relay.example/v2/relay/connect \
        --set trustRoot.baseURL=https://trust.example >/dev/null
    if helm template iscp deploy/helm/iscp --set profile=production >/dev/null 2>&1; then
        printf 'helm production render without required secrets unexpectedly succeeded\n' >&2
        exit 1
    fi
fi
invoke_go run ./tools/iscp-ci/cmd/iscp-ci helm-check
