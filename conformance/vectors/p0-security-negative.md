# P0 Security Negative Test Matrix

| ID | Rule | Expected Result |
| --- | --- | --- |
| NEG-001 | Duplicate JSON field | Canonical parser rejects input. |
| NEG-002 | Float in signed object | Canonical parser rejects input. |
| NEG-003 | Unknown top-level field | Schema/object parser rejects input. |
| NEG-004 | Ed25519 key used for X25519 | Crypto API rejects type mismatch. |
| NEG-005 | Unsigned descriptor in production | Profile gate rejects config/use. |
| NEG-006 | Bearer-only access in production | Profile gate rejects config/use. |
| NEG-007 | Plaintext debug in production | Profile gate rejects config/use. |
| NEG-008 | Session payload before ready | SDK refuses delivery. |
| NEG-009 | Route metadata tamper | AEAD authentication fails. |
| NEG-010 | Nonce or sequence replay | Envelope receiver rejects replay. |
| NEG-011 | Revoked access refresh | Relay rejects refresh. |
| NEG-012 | Revoked trust grant | Trust verification rejects grant. |
| NEG-013 | Grant audience mismatch | Trust verification rejects grant. |
| NEG-014 | Grant confirmation mismatch | Trust verification rejects grant. |
| NEG-015 | Logs contain secret-like material | Secret scanner fails. |

