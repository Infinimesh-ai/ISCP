#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
. "${script_dir}/common.sh"

cd "${ISCP_REPO_ROOT}"
invoke_go test ./conformance/... ./pkg/iscp/...
invoke_go run ./tools/iscp-cli/cmd/iscp conformance run --output conformance/report.json
invoke_go run ./tools/iscp-cli/cmd/iscp conformance validate-report --output conformance/report.json
