# Canonical JSON for ISCP v2

ISCP v2 uses a strict JSON canonicalization profile inspired by JCS, narrowed to
avoid ambiguity and implementation-dependent behavior.

## Rules

- Input must be valid UTF-8 JSON.
- Duplicate object properties are rejected.
- Floating point numbers are rejected.
- Integers are encoded in base-10 without leading zeroes.
- Object members are ordered lexicographically by Unicode code point.
- Strings are encoded using Go `encoding/json` compatible escaping.
- Unknown top-level fields are rejected by schema and Core SDK object parsers.
- Extensions are allowed only under an `extensions` object and only when the
  extension name is not marked critical by an unsupported `critical` entry.
- Signature fields are removed before canonicalization for signed objects.
- Bytes are represented as unpadded base64url strings.
- Timestamps use RFC3339 UTC with seconds precision unless the schema states
  otherwise.

## Deterministic Signature Input

```text
ISCP-V2-SIGNATURE\0<object_type>\0<canonical_json_bytes>
```

## Rejected Inputs

- Duplicate field names.
- `NaN`, `Infinity`, `-Infinity`, decimal numbers, or exponent notation.
- Unknown top-level fields.
- Critical extensions unsupported by the verifying implementation.
- Any signed object that changes canonical bytes after a JSON round trip.

## Canonical Test Vector Shape

```json
{
  "name": "device-proof-basic",
  "object_type": "iscp.device.proof.v2",
  "input": {},
  "canonical_hex": "",
  "signature_input_hex": ""
}
```

