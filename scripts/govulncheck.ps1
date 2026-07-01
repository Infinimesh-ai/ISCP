. "$PSScriptRoot/common.ps1"
Invoke-Go install golang.org/x/vuln/cmd/govulncheck@latest
Invoke-Go run golang.org/x/vuln/cmd/govulncheck@latest ./...

