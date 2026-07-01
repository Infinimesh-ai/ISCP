#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
. "${script_dir}/common.sh"

cd "${ISCP_REPO_ROOT}"
invoke_go install golang.org/x/vuln/cmd/govulncheck@latest
invoke_go run golang.org/x/vuln/cmd/govulncheck@latest ./...
