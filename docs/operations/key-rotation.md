# Key Rotation

Trust Root signing keys follow:

```text
next -> active -> retired -> revoked
```

Operational rules:

- Publish descriptors with active and next public keys before activation.
- Use active keys for new grants.
- Keep retired keys available for validation until all issued objects expire.
- Revoke compromised keys and invalidate affected grants.
- Audit every transition.

