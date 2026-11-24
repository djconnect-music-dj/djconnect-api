-- Only the actual first-key verifier continuation can populate this key DATA.
-- Legacy rows remain NULL and cannot reauthorize a role from status or load.
ALTER TABLE native_installation_first_key ADD COLUMN apple_key_id_b64 TEXT;
ALTER TABLE native_installation_first_key ADD COLUMN apple_public_key_spki_b64 TEXT;
ALTER TABLE native_installation_first_key ADD COLUMN apple_assertion_policy_json TEXT;
ALTER TABLE native_installation_first_key ADD COLUMN apple_evidence_expires_at_ms INTEGER;
ALTER TABLE native_installation_first_key ADD COLUMN apple_status_expires_at_ms INTEGER;
ALTER TABLE native_installation_first_key ADD COLUMN apple_counter INTEGER;
ALTER TABLE native_installation_first_key ADD COLUMN apple_counter_claim TEXT;
