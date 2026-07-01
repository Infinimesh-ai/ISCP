# 0001: V0.1 Version Scope

## Status

Accepted.

## Context

ISCP V0.1 is the first engineering implementation in this repository. The
protocol, schema, and API namespace uses `v2` for protocol semantics and object
names.

## Decision

`v2` means protocol version and schema namespace only. The engineering release
is V0.1, and this is the first implementation.

The project will not implement:

- V1 migration.
- V1 compatibility layers.
- Old API bridges.
- Old database upgrades.
- Old client adaptation.
- Historical behavior preservation.

## Consequences

- Protocol objects are designed directly for the V0.1 implementation.
- Database migrations start from an empty V0.1 schema.
- Tests and documentation must not treat V1 support as required work.
- If future compatibility is needed, it must be proposed as a new decision.

