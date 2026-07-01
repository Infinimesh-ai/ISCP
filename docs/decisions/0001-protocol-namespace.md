# 0001: Protocol Namespace

## Status

Accepted.

## Context

The protocol, schema, and API namespace uses `v2` in object names, JSON Schema
IDs, and REST paths.

## Decision

`v2` is the ISCP protocol namespace. It is part of the wire format and schema
identity, independent from repository release tags.

## Consequences

- Protocol objects, JSON Schemas, and REST paths keep stable `v2` names until a
  future protocol namespace is intentionally introduced.
- Repository release tags can evolve independently from protocol namespace
  naming.
