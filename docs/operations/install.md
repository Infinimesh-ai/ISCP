# Install

Install flows start from an empty ISCP environment.

## Local Compose

```bash
docker compose -f deploy/docker-compose/docker-compose.yaml up --build
```

Services:

- Relay: `http://localhost:8080`
- Trust Root: `http://localhost:8081`
- PostgreSQL 18: `localhost:5432`

## CLI Smoke Test

```bash
./scripts/test.sh
. ./scripts/common.sh
invoke_go run ./tools/iscp-cli/cmd/iscp demo local-e2e
```
