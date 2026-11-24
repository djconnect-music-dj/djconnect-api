-- Production credential namespaces; HA-dev qualification tables stay separate.
CREATE TABLE native_installation_pair_publications (
    credential_id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    pairing_generation TEXT NOT NULL,
    pair_binding TEXT NOT NULL,
    owner_binding TEXT NOT NULL,
    device_binding TEXT NOT NULL,
    core_key_thumbprint TEXT NOT NULL,
    request_expires_at_ms INTEGER NOT NULL,
    consent_revision INTEGER NOT NULL CHECK (consent_revision > 0),
    PRIMARY KEY (credential_id, operation_id)
);
CREATE TABLE native_installation_consent_withdrawals (
    credential_id TEXT NOT NULL,
    pair_binding TEXT NOT NULL,
    through_revision INTEGER NOT NULL CHECK (through_revision > 0),
    PRIMARY KEY (credential_id, pair_binding)
);
CREATE TABLE native_installation_key_retirements (
    credential_id TEXT NOT NULL,
    pair_binding TEXT NOT NULL,
    PRIMARY KEY (credential_id, pair_binding)
);
CREATE TABLE native_installation_key_decisions (
    credential_id TEXT NOT NULL,
    decision_id TEXT NOT NULL,
    expires_at_ms INTEGER NOT NULL,
    PRIMARY KEY (credential_id, decision_id)
);
CREATE INDEX native_installation_decision_expiry ON native_installation_key_decisions(expires_at_ms);
CREATE TABLE native_installation_first_key (
    credential_id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    installation_id TEXT NOT NULL UNIQUE,
    policy_id TEXT NOT NULL,
    pair_binding TEXT NOT NULL,
    original_request TEXT NOT NULL,
    challenge TEXT NOT NULL,
    expires_at_ms INTEGER NOT NULL,
    key_spki TEXT,
    transcript_sha256 TEXT,
    receipt TEXT,
    retired INTEGER NOT NULL DEFAULT 0 CHECK (retired IN (0, 1)),
    status_nonce TEXT,
    status_nonce_id TEXT,
    status_expires_at_ms INTEGER,
    PRIMARY KEY (credential_id, operation_id)
);
CREATE UNIQUE INDEX native_installation_one_key_per_pair
    ON native_installation_first_key(credential_id, pair_binding) WHERE receipt IS NOT NULL;
