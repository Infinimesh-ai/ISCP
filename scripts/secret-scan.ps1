$ErrorActionPreference = "Stop"
$patterns = @(
    'BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY',
    'refresh[_-]?credential["'']?\s*[:=]\s*["''][^"'']{8,}',
    'access[_-]?token["'']?\s*[:=]\s*["''][^"'']{8,}',
    'session[_-]?key["'']?\s*[:=]\s*["''][^"'']{8,}'
)

$files = Get-ChildItem -Recurse -File |
    Where-Object {
        $_.FullName -notmatch "\\.git\\" -and
        $_.FullName -notmatch "\\go\.sum$" -and
        $_.FullName -notmatch "\\conformance\\report\.json$" -and
        $_.FullName -notmatch "\\scripts\\secret-scan\.ps1$" -and
        $_.FullName -notmatch "\\pkg\\iscp\\logging\\redact\.go$"
    }

$hits = @()
foreach ($file in $files) {
    $text = Get-Content -Raw -ErrorAction SilentlyContinue -LiteralPath $file.FullName
    foreach ($pattern in $patterns) {
        if ($text -match $pattern) {
            $hits += "$($file.FullName): $pattern"
        }
    }
}

if ($hits.Count -gt 0) {
    $hits | ForEach-Object { Write-Error $_ }
    throw "secret scan failed"
}

Write-Host "secret scan passed"
