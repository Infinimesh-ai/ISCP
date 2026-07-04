$ErrorActionPreference = "Stop"

. "$PSScriptRoot/common.ps1"
Invoke-Go run ./tools/iscp-ci/cmd/iscp-ci traceability
