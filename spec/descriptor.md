# Descriptors

Descriptors publish service metadata and signing keys. V0.1 defines Relay and
Trust Root descriptors.

Signed descriptors use `iscp.signed_descriptor.v2` and include:

- `descriptor_type`
- `descriptor`
- `signature`
- `signed_by`
- `signed_at`

Production profile MUST reject unsigned descriptors. Pinning uses SHA-256 over
canonical descriptor bytes.

Descriptors MUST include key usage. A key published for descriptor signing MUST
NOT be accepted for Trust Grant signing unless that usage is explicitly present.

