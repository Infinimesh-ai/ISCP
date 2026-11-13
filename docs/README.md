# ISCP Documentation

This directory contains public project documentation for ISCP.

## API

- [OpenAPI 3.1](api/openapi.yaml)
- [Event catalog](api/events.md)

## Architecture

- [System architecture](architecture.md)

## Operations

- [Install](operations/install.md)
- [PostgreSQL 18 operations](operations/postgres.md)
- [Backup and restore](operations/backup-restore.md)
- [Key rotation](operations/key-rotation.md)
- [Upgrade policy](operations/upgrade.md)
- [Candidate duplex activation and SDK integration](operations/duplex.md)

## Security and Release

- [Security release gates](security/release-gates.md)
- [Release checklist](release/checklist.md)
- [Protocol namespace decision](decisions/0001-protocol-namespace.md)
- [Proposed duplex SDK decision](decisions/0002-duplex-sdk.md)
- [Proposed operation recovery decision](decisions/0003-operation-recovery.md)

## Development

- [Downstream implementation reconciliation](development/downstream-reconciliation.md)

## Protocol

Protocol documents live in the top-level [spec](../spec) directory. JSON
Schemas for established objects live in [schemas/json](../schemas/json).
Proposed bindings have separate [candidate schemas](../schemas/candidates):

- [Duplex Relay binding](../spec/relay-duplex.md)
- [HTTPS operation recovery](../spec/operation-recovery.md)

These candidates are optional and do not change the default reference transport.
