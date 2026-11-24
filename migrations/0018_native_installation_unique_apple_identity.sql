-- A verified App Attest identity belongs to one original registered key row.
-- Retired registered history remains a permanent veto; no lookup/adoption or
-- counter reset is authorized by a new installation principal or pairing.
CREATE UNIQUE INDEX native_installation_registered_apple_id_once
 ON native_installation_first_key(apple_key_id_b64)
 WHERE receipt IS NOT NULL AND apple_key_id_b64 IS NOT NULL;
CREATE UNIQUE INDEX native_installation_registered_apple_spki_once
 ON native_installation_first_key(apple_public_key_spki_b64)
 WHERE receipt IS NOT NULL AND apple_public_key_spki_b64 IS NOT NULL;
