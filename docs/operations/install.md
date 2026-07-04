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

## Helm Baseline

The Helm chart defaults to a local-lab reference deployment with in-memory
service state:

```bash
helm install iscp deploy/helm/iscp
```

For production, provide operator and database credentials through Kubernetes
Secrets and set the externally reachable Relay and Trust Root URLs:

```bash
kubectl create secret generic iscp-admin \
  --from-literal=admin-token='<operator token>'
kubectl create secret generic iscp-postgres \
  --from-literal=database-url='postgres://...'

helm upgrade --install iscp deploy/helm/iscp \
  --set profile=production \
  --set admin.existingSecret=iscp-admin \
  --set postgres.existingSecret=iscp-postgres \
  --set relay.allowedOrigins[0]=https://your-device-console.example \
  --set relay.baseURL=https://relay.example \
  --set relay.webSocketURL=wss://relay.example/v2/relay/connect \
  --set trustRoot.baseURL=https://trust.example
```

The chart rejects production rendering unless an admin secret, database URL or
database secret, and Relay allowed origins are configured.

## Production Profile

Production deployments must set:

```text
ISCP_PROFILE=production
ISCP_ADMIN_TOKEN=<operator token>
ISCP_ALLOWED_ORIGINS=https://your-device-console.example
ISCP_DATABASE_URL=postgres://...
```

`ISCP_ADMIN_TOKEN` is required for Relay admin APIs and Trust Root
authorization, revocation, key rotation, and audit APIs. Relay WebSocket
connections reject cross-origin browser upgrades unless the origin matches
`ISCP_ALLOWED_ORIGINS`, `ISCP_RELAY_BASE_URL`, or `ISCP_RELAY_WS_URL`.

Relay envelope submission requires an access credential in
`Authorization: Bearer <access-token>`, and the credential device must match the
envelope sender. Refresh credentials are single-use and are revoked when rotated.
With `ISCP_DATABASE_URL` set, Relay stores offline envelopes in PostgreSQL and
claims them with delivery leases during WebSocket delivery, so queued messages
survive process restarts and rolling deployments.
