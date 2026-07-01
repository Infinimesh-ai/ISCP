-- ISCP initial PostgreSQL 18 schema.

CREATE SCHEMA IF NOT EXISTS iscp_relay;
CREATE SCHEMA IF NOT EXISTS iscp_trust;

CREATE TABLE IF NOT EXISTS iscp_relay.schema_migrations (
    version bigint PRIMARY KEY,
    name text NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS iscp_trust.schema_migrations (
    version bigint PRIMARY KEY,
    name text NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS iscp_relay.devices (
    id uuid PRIMARY KEY,
    domain_id text NOT NULL,
    device_id text NOT NULL,
    identity_raw bytea NOT NULL,
    identity_canonical bytea NOT NULL,
    public_key_thumbprint text NOT NULL,
    status text NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(domain_id, device_id),
    CHECK (status IN ('active', 'revoked', 'disabled'))
);

CREATE TABLE IF NOT EXISTS iscp_relay.access_tokens (
    id uuid PRIMARY KEY,
    domain_id text NOT NULL,
    device_id text NOT NULL,
    token_hash bytea NOT NULL,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    UNIQUE(domain_id, token_hash)
);

CREATE TABLE IF NOT EXISTS iscp_relay.refresh_tokens (
    id uuid PRIMARY KEY,
    domain_id text NOT NULL,
    device_id text NOT NULL,
    refresh_hash bytea NOT NULL,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    rotated_to uuid,
    UNIQUE(domain_id, refresh_hash)
);

CREATE TABLE IF NOT EXISTS iscp_relay.pop_replay_cache (
    domain_id text NOT NULL,
    device_id text NOT NULL,
    nonce text NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY(domain_id, device_id, nonce)
);

CREATE TABLE IF NOT EXISTS iscp_relay.connections (
    id uuid PRIMARY KEY,
    domain_id text NOT NULL,
    device_id text NOT NULL,
    connection_id text NOT NULL,
    state text NOT NULL,
    connected_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    closed_at timestamptz,
    UNIQUE(domain_id, connection_id),
    CHECK (state IN ('challenge_sent', 'ready', 'closed'))
);

CREATE TABLE IF NOT EXISTS iscp_relay.messages (
    id uuid PRIMARY KEY,
    domain_id text NOT NULL,
    message_id text NOT NULL,
    sender_device_id text NOT NULL,
    recipient_device_id text NOT NULL,
    session_id text NOT NULL,
    payload_type text NOT NULL,
    route_metadata jsonb NOT NULL,
    envelope_raw bytea NOT NULL,
    envelope_canonical bytea NOT NULL,
    priority integer NOT NULL DEFAULT 0,
    queued_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    delivered_at timestamptz,
    CHECK (priority >= 0 AND priority <= 9),
    UNIQUE(domain_id, message_id)
);

CREATE TABLE IF NOT EXISTS iscp_relay.delivery_receipts (
    id uuid PRIMARY KEY,
    domain_id text NOT NULL,
    receipt_id text NOT NULL,
    message_id text NOT NULL,
    relay_id text NOT NULL,
    status text NOT NULL,
    receipt_raw bytea NOT NULL,
    receipt_canonical bytea NOT NULL,
    issued_at timestamptz NOT NULL,
    UNIQUE(domain_id, receipt_id),
    CHECK (status IN ('accepted', 'queued', 'delivered_to_connection', 'expired', 'rejected'))
);

CREATE TABLE IF NOT EXISTS iscp_relay.audit_log (
    id uuid PRIMARY KEY,
    domain_id text NOT NULL,
    event_type text NOT NULL,
    actor_device_id text,
    subject_id text,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    previous_hash bytea,
    entry_hash bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_relay_devices_domain_status ON iscp_relay.devices(domain_id, status);
CREATE INDEX IF NOT EXISTS idx_relay_access_expiry ON iscp_relay.access_tokens(domain_id, expires_at) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_relay_refresh_expiry ON iscp_relay.refresh_tokens(domain_id, expires_at) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_relay_messages_recipient ON iscp_relay.messages(domain_id, recipient_device_id, priority DESC, queued_at);
CREATE INDEX IF NOT EXISTS idx_relay_messages_expiry ON iscp_relay.messages(domain_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_relay_audit_domain_created ON iscp_relay.audit_log(domain_id, created_at);

CREATE TABLE IF NOT EXISTS iscp_trust.devices (
    id uuid PRIMARY KEY,
    domain_id text NOT NULL,
    device_id text NOT NULL,
    identity_raw bytea NOT NULL,
    identity_canonical bytea NOT NULL,
    public_key_thumbprint text NOT NULL,
    status text NOT NULL DEFAULT 'submitted',
    device_record_version bigint NOT NULL DEFAULT 1,
    revocation_epoch bigint NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(domain_id, device_id),
    CHECK (status IN ('submitted', 'authorized', 'revoked', 'disabled')),
    CHECK (device_record_version > 0),
    CHECK (revocation_epoch >= 0)
);

CREATE TABLE IF NOT EXISTS iscp_trust.permissions (
    id uuid PRIMARY KEY,
    domain_id text NOT NULL,
    permission text NOT NULL,
    risk_class text NOT NULL DEFAULT 'normal',
    max_ttl_seconds integer NOT NULL,
    max_cache_staleness_seconds integer NOT NULL DEFAULT 0,
    UNIQUE(domain_id, permission)
);

CREATE TABLE IF NOT EXISTS iscp_trust.grants (
    id uuid PRIMARY KEY,
    domain_id text NOT NULL,
    grant_id text NOT NULL,
    subject_device_id text NOT NULL,
    audience text NOT NULL,
    confirmation_thumbprint text NOT NULL,
    grant_raw bytea NOT NULL,
    grant_canonical bytea NOT NULL,
    not_before timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revocation_epoch bigint NOT NULL,
    revoked_at timestamptz,
    UNIQUE(domain_id, grant_id)
);

CREATE TABLE IF NOT EXISTS iscp_trust.revocations (
    id uuid PRIMARY KEY,
    domain_id text NOT NULL,
    subject_type text NOT NULL,
    subject_id text NOT NULL,
    revocation_epoch bigint NOT NULL,
    reason text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (subject_type IN ('device', 'grant')),
    UNIQUE(domain_id, subject_type, subject_id, revocation_epoch)
);

CREATE TABLE IF NOT EXISTS iscp_trust.signing_keys (
    id uuid PRIMARY KEY,
    domain_id text NOT NULL,
    key_id text NOT NULL,
    public_key text NOT NULL,
    key_use text NOT NULL,
    state text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    activated_at timestamptz,
    retired_at timestamptz,
    revoked_at timestamptz,
    UNIQUE(domain_id, key_id),
    CHECK (key_use IN ('descriptor-signature', 'grant-signature')),
    CHECK (state IN ('next', 'active', 'retired', 'revoked'))
);

CREATE TABLE IF NOT EXISTS iscp_trust.policy_versions (
    id uuid PRIMARY KEY,
    domain_id text NOT NULL,
    version bigint NOT NULL,
    policy jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(domain_id, version)
);

CREATE TABLE IF NOT EXISTS iscp_trust.audit_log (
    id uuid PRIMARY KEY,
    domain_id text NOT NULL,
    event_type text NOT NULL,
    actor_id text,
    subject_id text,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    previous_hash bytea,
    entry_hash bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_trust_devices_domain_status ON iscp_trust.devices(domain_id, status);
CREATE INDEX IF NOT EXISTS idx_trust_grants_subject ON iscp_trust.grants(domain_id, subject_device_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_trust_revocations_subject ON iscp_trust.revocations(domain_id, subject_type, subject_id);
CREATE INDEX IF NOT EXISTS idx_trust_keys_state ON iscp_trust.signing_keys(domain_id, state, key_use);
CREATE INDEX IF NOT EXISTS idx_trust_audit_domain_created ON iscp_trust.audit_log(domain_id, created_at);

INSERT INTO iscp_relay.schema_migrations(version, name)
VALUES (1, 'init')
ON CONFLICT (version) DO NOTHING;

INSERT INTO iscp_trust.schema_migrations(version, name)
VALUES (1, 'init')
ON CONFLICT (version) DO NOTHING;
