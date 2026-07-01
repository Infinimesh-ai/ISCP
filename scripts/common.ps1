Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-GoCommand {
    $go = Get-Command go -ErrorAction SilentlyContinue
    if ($null -ne $go) {
        return @($go.Source)
    }

    $docker = Get-Command docker -ErrorAction SilentlyContinue
    if ($null -eq $docker) {
        throw "Go 1.25.x is not installed and Docker is not available for fallback execution."
    }

    $workspace = (Resolve-Path ".").Path
    return @(
        "docker", "run", "--rm",
        "-e", "ISCP_PROFILE",
        "-e", "ISCP_RELAY_ENDPOINT",
        "-e", "ISCP_TRUST_ENDPOINT",
        "-v", "${workspace}:/workspace",
        "-w", "/workspace",
        "golang:1.25"
    )
}

function Invoke-Go {
    param(
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]] $Args
    )

    $cmd = Get-GoCommand
    if ($cmd.Count -eq 1) {
        & $cmd[0] @Args
        if ($LASTEXITCODE -ne 0) {
            throw "go $($Args -join ' ') failed with exit code $LASTEXITCODE"
        }
        return
    }

    & $cmd[0] $cmd[1..($cmd.Count - 1)] go @Args
    if ($LASTEXITCODE -ne 0) {
        throw "go $($Args -join ' ') failed with exit code $LASTEXITCODE"
    }
}
