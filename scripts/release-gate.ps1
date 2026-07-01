. "$PSScriptRoot/common.ps1"

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$distDir = Join-Path $root "dist"
$summaryPath = Join-Path $distDir "release-gate-summary.json"
$composeFile = Join-Path $root "deploy/docker-compose/docker-compose.yaml"
New-Item -ItemType Directory -Force -Path $distDir | Out-Null

function Get-EnvOrDefault {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Name,
        [Parameter(Mandatory = $true)]
        [string] $Default
    )

    $value = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($value)) {
        return $Default
    }
    return $value
}

function Get-HostProbeAddress {
    param(
        [Parameter(Mandatory = $true)]
        [string] $BindAddress
    )

    if ($BindAddress -eq "0.0.0.0" -or $BindAddress -eq "::" -or $BindAddress -eq "[::]") {
        return "127.0.0.1"
    }
    return $BindAddress
}

function Test-TcpPortAvailable {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Address,
        [Parameter(Mandatory = $true)]
        [int] $Port
    )

    $listener = $null
    try {
        $ip = [System.Net.IPAddress]::Parse($Address)
        $listener = [System.Net.Sockets.TcpListener]::new($ip, $Port)
        $listener.Start()
        return $true
    } catch {
        return $false
    } finally {
        if ($null -ne $listener) {
            $listener.Stop()
        }
    }
}

function Get-FreeTcpPort {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Address
    )

    $listener = $null
    try {
        $ip = [System.Net.IPAddress]::Parse($Address)
        $listener = [System.Net.Sockets.TcpListener]::new($ip, 0)
        $listener.Start()
        return $listener.LocalEndpoint.Port.ToString()
    } finally {
        if ($null -ne $listener) {
            $listener.Stop()
        }
    }
}

function Resolve-ComposePort {
    param(
        [Parameter(Mandatory = $true)]
        [string] $EnvName,
        [Parameter(Mandatory = $true)]
        [string] $DefaultPort,
        [Parameter(Mandatory = $true)]
        [string] $BindAddress
    )

    $configured = [Environment]::GetEnvironmentVariable($EnvName)
    if (![string]::IsNullOrWhiteSpace($configured)) {
        return $configured
    }

    $null = $DefaultPort
    return Get-FreeTcpPort $BindAddress
}

function Invoke-DockerCompose {
    param(
        [Parameter(Mandatory = $true)]
        [string[]] $ComposeArgs
    )

    $docker = Get-Command docker -ErrorAction SilentlyContinue
    if ($null -eq $docker) {
        throw "Docker is required for release gate Compose service validation."
    }
    if (!(Test-Path $composeFile)) {
        throw "Compose file is missing: $composeFile"
    }

    & $docker.Source compose -f $composeFile @ComposeArgs
    if ($LASTEXITCODE -ne 0) {
        throw "docker compose $($ComposeArgs -join ' ') failed with exit code $LASTEXITCODE"
    }
}

function Wait-HTTPReady {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Name,
        [Parameter(Mandatory = $true)]
        [string] $Endpoint,
        [int] $TimeoutSeconds = 180
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $lastError = ""
    while ((Get-Date) -lt $deadline) {
        try {
            foreach ($path in @("/healthz", "/version")) {
                $uri = "$Endpoint$path"
                $resp = Invoke-WebRequest -Uri $uri -UseBasicParsing -TimeoutSec 3
                if ($resp.StatusCode -lt 200 -or $resp.StatusCode -ge 300) {
                    throw "$uri returned HTTP $($resp.StatusCode)"
                }
            }
            return
        } catch {
            $lastError = $_.Exception.Message
            Start-Sleep -Seconds 2
        }
    }

    throw "$Name did not become ready at $Endpoint within $TimeoutSeconds seconds. Last error: $lastError"
}

function Start-ComposeServices {
    $bindAddress = Get-EnvOrDefault "ISCP_BIND_ADDR" "127.0.0.1"
    $probeAddress = Get-HostProbeAddress $bindAddress
    $relayPort = Resolve-ComposePort "ISCP_RELAY_PORT" "8080" $probeAddress
    $trustPort = Resolve-ComposePort "ISCP_TRUST_PORT" "8081" $probeAddress
    $postgresPort = Resolve-ComposePort "ISCP_POSTGRES_PORT" "5432" $probeAddress

    $env:ISCP_BIND_ADDR = $bindAddress
    $env:ISCP_RELAY_PORT = $relayPort
    $env:ISCP_TRUST_PORT = $trustPort
    $env:ISCP_POSTGRES_PORT = $postgresPort

    $null = Invoke-DockerCompose @("up", "--build", "--detach", "postgres", "relay", "trust-root")

    $relayProbeEndpoint = "http://${probeAddress}:$relayPort"
    $trustProbeEndpoint = "http://${probeAddress}:$trustPort"
    Wait-HTTPReady "Relay Reference Service" $relayProbeEndpoint
    Wait-HTTPReady "Trust Root Reference Service" $trustProbeEndpoint

    $goCommand = Get-GoCommand
    $goExecution = "local-go"
    $runnerAddress = $probeAddress
    if ($goCommand.Count -gt 1) {
        $goExecution = "docker-fallback"
        $runnerAddress = "host.docker.internal"
    }

    $env:ISCP_RELAY_ENDPOINT = "http://${runnerAddress}:$relayPort"
    $env:ISCP_TRUST_ENDPOINT = "http://${runnerAddress}:$trustPort"

    return [ordered]@{
        compose_file = "deploy/docker-compose/docker-compose.yaml"
        services = @("postgres", "relay", "trust-root")
        bind_address = $bindAddress
        postgres_port = $postgresPort
        host_probe = [ordered]@{
            relay_endpoint = $relayProbeEndpoint
            trust_endpoint = $trustProbeEndpoint
        }
        conformance = [ordered]@{
            go_execution = $goExecution
            relay_endpoint = $env:ISCP_RELAY_ENDPOINT
            trust_endpoint = $env:ISCP_TRUST_ENDPOINT
        }
    }
}

$gates = @(
    @{ name = "compose-services"; command = "docker compose"; args = @("up", "--build", "--detach", "postgres", "relay", "trust-root") },
    @{ name = "test"; command = "./scripts/test.ps1"; args = @() },
    @{ name = "conformance"; command = "./scripts/conformance.ps1"; args = @() },
    @{ name = "secret-scan"; command = "./scripts/secret-scan.ps1"; args = @() },
    @{ name = "govulncheck"; command = "./scripts/govulncheck.ps1"; args = @() },
    @{ name = "gosec"; command = "./scripts/gosec.ps1"; args = @() },
    @{ name = "generate-openapi"; command = "./scripts/generate-openapi.ps1"; args = @() },
    @{ name = "generate-schemas"; command = "./scripts/generate-schemas.ps1"; args = @() },
    @{ name = "sbom"; command = "./scripts/sbom.ps1"; args = @() },
    @{ name = "conformance-release-validation"; command = "go"; args = @("run", "./tools/iscp-cli/cmd/iscp", "conformance", "validate-report", "--release", "--output", "conformance/report.json") }
)

$results = @()
$failed = $false

foreach ($gate in $gates) {
    $started = (Get-Date).ToUniversalTime()
    $result = [ordered]@{
        name = $gate.name
        command = $gate.command
        started_at = $started.ToString("o")
        status = "pass"
        duration_ms = 0
        error = $null
        details = $null
    }
    try {
        if ($gate.name -eq "compose-services") {
            $result.details = Start-ComposeServices
        } elseif ($gate.command -eq "go") {
            $goArgs = [string[]]$gate.args
            Invoke-Go @goArgs
        } else {
            & $gate.command @($gate.args)
            if ($LASTEXITCODE -ne 0) {
                throw "$($gate.command) failed with exit code $LASTEXITCODE"
            }
        }
    } catch {
        $failed = $true
        $result.status = "fail"
        $result.error = $_.Exception.Message
    }
    $ended = (Get-Date).ToUniversalTime()
    $result.duration_ms = [int64]($ended - $started).TotalMilliseconds
    $results += $result
    if ($failed) {
        break
    }
}

$summary = [ordered]@{
    type = "iscp.release_gate.summary.v2"
    generated_at = (Get-Date).ToUniversalTime().ToString("o")
    release_decision = $(if ($failed) { "no-go" } else { "go" })
    gates = $results
}

$summary | ConvertTo-Json -Depth 6 | Set-Content -Encoding utf8 -Path $summaryPath

if ($failed) {
    throw "release gate failed; see $summaryPath"
}

Write-Host "release gate passed; see $summaryPath"
