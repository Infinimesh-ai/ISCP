. "$PSScriptRoot/common.ps1"

$helm = Get-Command helm -ErrorAction SilentlyContinue
if ($null -ne $helm) {
    & $helm.Source template iscp deploy/helm/iscp | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "helm template local-lab failed with exit code $LASTEXITCODE"
    }
    & $helm.Source template iscp deploy/helm/iscp `
        --set profile=production `
        --set admin.existingSecret=iscp-admin `
        --set postgres.existingSecret=iscp-postgres `
        --set "relay.allowedOrigins[0]=https://console.example" `
        --set relay.baseURL=https://relay.example `
        --set relay.webSocketURL=wss://relay.example/v2/relay/connect `
        --set trustRoot.baseURL=https://trust.example | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "helm template production failed with exit code $LASTEXITCODE"
    }
    & $helm.Source template iscp deploy/helm/iscp --set profile=production *> $null
    if ($LASTEXITCODE -eq 0) {
        throw "helm production render without required secrets unexpectedly succeeded"
    }
}

Invoke-Go run ./tools/iscp-ci/cmd/iscp-ci helm-check
