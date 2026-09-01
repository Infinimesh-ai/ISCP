# Identity and Proof

Device identities are public objects containing device ID, domain ID, Ed25519
public key, key usage, creation time, and optional metadata. Long-term private
keys are generated and stored only by the device.

Device proofs are signed statements over a challenge, audience, nonce, and
issued-at timestamp. The proof signature input is the canonical proof object
without `signature`.

Proof verification MUST reject:

- Unsupported key type.
- Expired challenge.
- Audience mismatch.
- Nonce replay.
- Signature mismatch.
- Unknown top-level fields.
- An identity `kid` that is not the thumbprint of the submitted public key.
- A proof signature `kid` that does not match the identity `kid`.

Verifiers that authenticate against previously stored device state MUST verify
the proof against the stored public key for the device, not against key
material submitted in the request. Comparing a submitted `kid` against a stored
thumbprint is not a substitute for verifying against the stored key.

