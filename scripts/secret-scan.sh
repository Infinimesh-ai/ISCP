#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
. "${script_dir}/common.sh"

cd "${ISCP_REPO_ROOT}"

patterns=(
    'BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY'
    "refresh[_-]?credential[\"']?[[:space:]]*[:=][[:space:]]*[\"'][^\"']{8,}"
    "access[_-]?token[\"']?[[:space:]]*[:=][[:space:]]*[\"'][^\"']{8,}"
    "session[_-]?key[\"']?[[:space:]]*[:=][[:space:]]*[\"'][^\"']{8,}"
)

hits=0
while IFS= read -r -d '' file; do
    for pattern in "${patterns[@]}"; do
        if grep -Iq . "${file}" 2>/dev/null && grep -Eq "${pattern}" "${file}" 2>/dev/null; then
            printf '%s: %s\n' "${ISCP_REPO_ROOT}/${file#./}" "${pattern}" >&2
            hits=1
        fi
    done
done < <(
    find . -type f \
        ! -path './.git/*' \
        ! -path './go.sum' \
        ! -path './conformance/report.json' \
        ! -path './scripts/secret-scan.ps1' \
        ! -path './scripts/secret-scan.sh' \
        ! -path './pkg/iscp/logging/redact.go' \
        -print0
)

if [[ "${hits}" -ne 0 ]]; then
    printf 'secret scan failed\n' >&2
    exit 1
fi

printf 'secret scan passed\n'
