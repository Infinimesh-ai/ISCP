Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$distDir = Join-Path $root "dist"
$summaryPath = Join-Path $distDir "openapi-check.json"
$openapiPath = Join-Path $root "docs/api/openapi.yaml"
$routeFiles = @(
    (Join-Path $root "services/relay-reference/internal/relay/server.go"),
    (Join-Path $root "services/trust-root-reference/internal/trust/server.go")
)

New-Item -ItemType Directory -Force -Path $distDir | Out-Null

$expectedMethods = [ordered]@{
    "/.well-known/iscp/relay" = "get"
    "/v2/relay/devices/bind-self" = "post"
    "/v2/relay/devices/register-with-ticket" = "post"
    "/v2/relay/devices/refresh-access" = "post"
    "/v2/relay/devices/revoke-access" = "post"
    "/v2/relay/connect" = "get"
    "/v2/relay/envelopes" = "post"
    "/v2/relay/admin/devices" = "get"
    "/v2/relay/admin/connections" = "get"
    "/v2/relay/admin/messages" = "get"
    "/.well-known/iscp/trust-root" = "get"
    "/v2/trust/devices/submit" = "post"
    "/v2/trust/devices/authorize" = "post"
    "/v2/trust/devices/revoke" = "post"
    "/v2/trust/devices/status" = "get"
    "/v2/trust/grants/verify" = "post"
    "/v2/trust/grants/status" = "get"
    "/v2/trust/revocations" = "get"
    "/v2/trust/keys/rotate" = "post"
    "/v2/trust/admin/audit" = "get"
}

$errors = @()
$openapiPaths = @()
$serviceRoutes = @()
$content = ""

if (!(Test-Path $openapiPath)) {
    $errors += "docs/api/openapi.yaml is missing"
} else {
    $content = Get-Content -Raw -Path $openapiPath
    if ($content -notmatch '(?m)^openapi:\s*3\.1\.0\s*$') {
        $errors += "docs/api/openapi.yaml must declare openapi: 3.1.0"
    }
    if ($content -notmatch '(?m)^components:\s*$' -or $content -notmatch '(?m)^  schemas:\s*$' -or $content -notmatch '(?m)^    Error:\s*$') {
        $errors += "docs/api/openapi.yaml must include components.schemas.Error"
    }
    $openapiPaths = @([regex]::Matches($content, '(?m)^  (/[^:]+):\s*$') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
    if ($openapiPaths.Count -eq 0) {
        $errors += "docs/api/openapi.yaml has no path entries"
    }
}

foreach ($routeFile in $routeFiles) {
    if (!(Test-Path $routeFile)) {
        $errors += "route source file is missing: $routeFile"
        continue
    }
    $routeSource = Get-Content -Raw -Path $routeFile
    $serviceRoutes += @([regex]::Matches($routeSource, 'HandleFunc\("([^"]+)"') | ForEach-Object { $_.Groups[1].Value })
}

$publicServiceRoutes = @(
    $serviceRoutes |
        Where-Object { $_ -like "/v2/*" -or $_ -like "/.well-known/iscp/*" } |
        Sort-Object -Unique
)
$openapiPublicPaths = @(
    $openapiPaths |
        Where-Object { $_ -like "/v2/*" -or $_ -like "/.well-known/iscp/*" } |
        Sort-Object -Unique
)

$missingFromOpenAPI = @($publicServiceRoutes | Where-Object { $_ -notin $openapiPaths })
$notImplementedByServices = @($openapiPublicPaths | Where-Object { $_ -notin $publicServiceRoutes })
$missingFromManifest = @($publicServiceRoutes | Where-Object { $_ -notin $expectedMethods.Keys })
$manifestNotImplemented = @($expectedMethods.Keys | Where-Object { $_ -notin $publicServiceRoutes })

if ($missingFromOpenAPI.Count -gt 0) {
    $errors += "OpenAPI is missing service routes: $($missingFromOpenAPI -join ', ')"
}
if ($notImplementedByServices.Count -gt 0) {
    $errors += "OpenAPI documents routes not implemented by the reference services: $($notImplementedByServices -join ', ')"
}
if ($missingFromManifest.Count -gt 0) {
    $errors += "OpenAPI method manifest is missing service routes: $($missingFromManifest -join ', ')"
}
if ($manifestNotImplemented.Count -gt 0) {
    $errors += "OpenAPI method manifest contains routes not implemented by the reference services: $($manifestNotImplemented -join ', ')"
}

if ($content -ne "") {
    foreach ($path in $expectedMethods.Keys) {
        $method = $expectedMethods[$path]
        $sectionPattern = "(?ms)^  " + [regex]::Escape($path) + ":\s*\r?\n(?<section>.*?)(?=^  /|\z)"
        $sectionMatch = [regex]::Match($content, $sectionPattern)
        if (!$sectionMatch.Success) {
            continue
        }
        if ($sectionMatch.Groups["section"].Value -notmatch "(?m)^    $($method):\s*$") {
            $errors += "OpenAPI path $path must document $($method.ToUpperInvariant())"
        }
        if ($sectionMatch.Groups["section"].Value -notmatch '(?m)^      responses:\s*$') {
            $errors += "OpenAPI path $path must document responses"
        }
    }
}

$checkedPaths = @(
    foreach ($path in $expectedMethods.Keys) {
        [ordered]@{
            path = $path
            method = $expectedMethods[$path]
        }
    }
)

$summary = [ordered]@{
    type = "iscp.openapi.validation.v2"
    generated_at = (Get-Date).ToUniversalTime().ToString("o")
    openapi_file = "docs/api/openapi.yaml"
    route_sources = @(
        "services/relay-reference/internal/relay/server.go",
        "services/trust-root-reference/internal/trust/server.go"
    )
    status = $(if ($errors.Count -eq 0) { "pass" } else { "fail" })
    openapi_path_count = $openapiPublicPaths.Count
    service_route_count = $publicServiceRoutes.Count
    checked_paths = $checkedPaths
    missing_from_openapi = $missingFromOpenAPI
    not_implemented_by_services = $notImplementedByServices
    errors = $errors
}

$summary | ConvertTo-Json -Depth 8 | Set-Content -Encoding utf8 -Path $summaryPath

if ($errors.Count -gt 0) {
    throw "OpenAPI validation failed; see dist/openapi-check.json"
}

Write-Host "OpenAPI validation passed; see dist/openapi-check.json"
