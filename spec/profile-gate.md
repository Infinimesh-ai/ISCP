# Profile Gates

Profiles control unsafe development behavior.

| Profile | Unsigned Descriptor | Bearer-only Access | Plaintext Debug |
| --- | --- | --- | --- |
| `production` | denied | denied | denied |
| `staging` | denied | denied | denied |
| `local-lab` | allowed only with explicit flag | allowed only with explicit flag | allowed only with `allow_debug_secrets` |

Config validation MUST fail closed for unknown profiles.

