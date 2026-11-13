# 0002: Reusable duplex Relay SDK with explicit transport selection

Status: proposed.

Downstream applications currently implement socket ownership, access rotation,
signed admission validation and durable receipt recovery outside the Core SDK.
These are connectivity responsibilities shared by applications, so they belong
in reusable ISCP packages and an independently runnable reference service.

The contribution extracts the tested protocol and server from the downstream
ISCP fork, and reconciles newer client fixes from SparkClaw. It does not import
SparkClaw's workbench API, Owner/Client database, application operation table,
UI, deployment endpoints or platform credential-storage policy.

The official reference transport remains the default. Duplex is an explicit
alternative selected with `ISCP_RELAY_TRANSPORT=duplex-v1`. Its admission history
cannot coexist with unfenced legacy writers in the same scope: a deployment
must initialize a new, never-served scope or perform an audited maintenance
cutover. Selecting duplex retires that scope's old transport endpoints with an
explicit upgrade response. It does not silently change other deployments.

Protocol identifiers and signature contexts retain the tested candidate wire
bytes. Schemas stay under `schemas/candidates`, separate from the established
v2 object manifest. A new protocol version or stable-release designation is an
upstream review decision, not implied by this implementation.

The client takes a pinned identity, endpoints and a credential-provider API.
Transport code does not issue application Grants or decide business permission.
The application supplies its verified authority policy and durable installation
hook; the generic provider owns coalesced recovery and cancellation. A persistent
transport journal uses an explicit storage key rather than deriving storage
access by exporting a device's signing key.

Alternatives considered: importing the entire downstream fork would also import
application profiles and default endpoint retirement; retaining only wire
schemas would leave the same reusable runtime duplicated in every consumer.
The SDK/server extraction addresses both problems with public implementations,
examples and compatibility tests.

See [the candidate specification](../../spec/relay-duplex.md) and
[source reconciliation](../development/downstream-reconciliation.md).
