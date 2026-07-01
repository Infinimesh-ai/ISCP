# ISCP Error Model v2

Errors are machine-readable and safe to log.

```json
{
  "type": "iscp.error.v2",
  "code": "ISCPSIG001",
  "message": "signature verification failed",
  "retryable": false,
  "details": {},
  "request_id": "req_..."
}
```

`details` MUST NOT contain private keys, access token plaintext, refresh
credential plaintext, session keys, or plaintext payloads.

## Code Families

| Prefix | Family |
| --- | --- |
| `ISCPCAN` | Canonical JSON and schema parsing |
| `ISCPSIG` | Signatures and proofs |
| `ISCPKEY` | Key handling and thumbprints |
| `ISCPTRUST` | Trust Grant and revocation |
| `ISCPSESSION` | Session establishment and readiness |
| `ISCPENV` | Envelope encryption, AAD, replay |
| `ISCPACCESS` | Relay access and refresh credentials |
| `ISCPPROV` | Provisioning and pairing |
| `ISCPDB` | PostgreSQL repository and migrations |
| `ISCPCFG` | Configuration and profile gates |
| `ISCPOBS` | Logging, metrics, tracing, redaction |

