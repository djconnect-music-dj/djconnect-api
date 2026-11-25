-- A new original challenge and actual native-key counter advancement are
-- required for role reauthorization. Neither status nor UNKNOWN is reopened.
CREATE TABLE native_installation_role_challenges (
 id TEXT PRIMARY KEY,
 credential_id TEXT NOT NULL,
 credential_hash TEXT NOT NULL,
 ha_install_id TEXT NOT NULL,
 native_operation_id TEXT NOT NULL,
 native_receipt_json TEXT NOT NULL,
 publication_operation_id TEXT NOT NULL,
 consent_revision INTEGER NOT NULL,
 request_json TEXT NOT NULL,
 challenge_json TEXT NOT NULL,
 expires_at_ms INTEGER NOT NULL,
 claim_id TEXT NOT NULL,
 outcome TEXT NOT NULL CHECK(outcome IN ('pending','verifying','enrolled','rejected','unknown')),
 ack_json TEXT,
 UNIQUE(credential_id,publication_operation_id)
);
