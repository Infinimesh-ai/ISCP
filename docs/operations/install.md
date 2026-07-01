# Install

Install flows start from an empty ISCP environment.

## Local Compose

```powershell
docker compose -f deploy/docker-compose/docker-compose.yaml up --build
```

Services:

- Relay: `http://localhost:8080`
- Trust Root: `http://localhost:8081`
- PostgreSQL 18: `localhost:5432`

## CLI Smoke Test

```powershell
./scripts/test.ps1
. ./scripts/common.ps1; Invoke-Go run ./tools/iscp-cli/cmd/iscp demo local-e2e
```
