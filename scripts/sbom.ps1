$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path "dist" | Out-Null
$doc = @{
  bomFormat = "CycloneDX"
  specVersion = "1.5"
  version = 1
  metadata = @{
    component = @{
      type = "application"
      name = "iscp"
      version = "0.1.0"
    }
  }
  components = @(
    @{ type = "library"; name = "golang.org/x/crypto"; version = "v0.31.0" },
    @{ type = "library"; name = "github.com/jackc/pgx/v5"; version = "v5.9.2" },
    @{ type = "library"; name = "github.com/gorilla/websocket"; version = "v1.5.3" }
  )
}
$doc | ConvertTo-Json -Depth 10 | Set-Content -Encoding UTF8 -Path "dist/sbom.cdx.json"
Write-Host "dist/sbom.cdx.json"
