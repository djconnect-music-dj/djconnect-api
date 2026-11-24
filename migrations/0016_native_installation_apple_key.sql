-- Only the actual first-key verifier continuation can populate this key DATA.
-- Legacy rows remain NULL and cannot reauthorize a role from status or load.
ALTER TABLE native_installation_first_key ADD COLUMN apple_key_id_b64 TEXT;
ALTER TABLE native_installation_first_key ADD COLUMN apple_public_key_spki_b64 TEXT;
ALTER TABLE native_installation_first_key ADD COLUMN apple_assertion_policy_json TEXT;
ALTER TABLE native_installation_first_key ADD COLUMN apple_evidence_expires_at_ms INTEGER;
ALTER TABLE native_installation_first_key ADD COLUMN apple_status_expires_at_ms INTEGER;
ALTER TABLE native_installation_first_key ADD COLUMN apple_counter INTEGER;
ALTER TABLE native_installation_first_key ADD COLUMN apple_counter_claim TEXT;
CREATE TRIGGER native_surface_apple_identity_changed
AFTER UPDATE OF apple_key_id_b64,apple_public_key_spki_b64,apple_assertion_policy_json,apple_evidence_expires_at_ms,apple_status_expires_at_ms
ON native_installation_first_key
WHEN NEW.apple_key_id_b64 IS NOT OLD.apple_key_id_b64 OR NEW.apple_public_key_spki_b64 IS NOT OLD.apple_public_key_spki_b64
 OR NEW.apple_assertion_policy_json IS NOT OLD.apple_assertion_policy_json
 OR NEW.apple_evidence_expires_at_ms IS NOT OLD.apple_evidence_expires_at_ms OR NEW.apple_status_expires_at_ms IS NOT OLD.apple_status_expires_at_ms
BEGIN
 UPDATE surface_push_delegations SET revoked_at=COALESCE(revoked_at,CAST(unixepoch('subsec')*1000 AS INTEGER))
 WHERE id IN(SELECT delegation_id FROM native_installation_surface_bindings
  WHERE credential_id=OLD.credential_id AND native_operation_id=OLD.operation_id);
END;
