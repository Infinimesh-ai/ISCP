. "$PSScriptRoot/common.ps1"
Invoke-Go test ./conformance/... ./pkg/iscp/...
Invoke-Go run ./tools/iscp-cli/cmd/iscp conformance run --output conformance/report.json
Invoke-Go run ./tools/iscp-cli/cmd/iscp conformance validate-report --output conformance/report.json
