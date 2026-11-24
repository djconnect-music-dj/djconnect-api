-- Genuine native first trust remains distinct from each bounded Widget role.
CREATE TABLE native_installation_surface_bindings (
 delegation_id TEXT PRIMARY KEY REFERENCES surface_push_delegations(id),
 credential_id TEXT NOT NULL,
 credential_hash TEXT NOT NULL,
 ha_install_id TEXT NOT NULL,
 native_operation_id TEXT NOT NULL,
 native_receipt_json TEXT NOT NULL,
 pair_binding TEXT NOT NULL,
 consent_revision INTEGER NOT NULL CHECK(consent_revision>0),
 enrolment_sha256 TEXT NOT NULL,
 scope_digest TEXT NOT NULL
);
CREATE VIEW native_installation_live_delegations AS
 SELECT d.* FROM surface_push_delegations d
 JOIN native_installation_surface_bindings n ON n.delegation_id=d.id AND n.scope_digest=d.scope_digest
 JOIN install_tokens i ON i.id=n.credential_id AND i.token_hash=n.credential_hash
  AND i.ha_install_id=n.ha_install_id AND i.disabled=0
 JOIN native_installation_first_key k ON k.credential_id=n.credential_id
  AND k.operation_id=n.native_operation_id AND k.receipt=n.native_receipt_json AND k.retired=0
 JOIN native_installation_pair_publications p ON p.credential_id=n.credential_id
  AND p.operation_id=n.native_operation_id AND p.pair_binding=n.pair_binding
  AND p.consent_revision=n.consent_revision
  AND json_extract(k.original_request,'$.pairing_generation')=p.pairing_generation
  AND json_extract(k.original_request,'$.pair_binding')=p.pair_binding
  AND json_extract(k.original_request,'$.owner_binding')=p.owner_binding
  AND json_extract(k.original_request,'$.device_binding')=p.device_binding
  AND json_extract(k.original_request,'$.core_key_thumbprint')=p.core_key_thumbprint
 WHERE d.revoked_at IS NULL AND d.expires_at>CAST(unixepoch('subsec')*1000 AS INTEGER)
 AND NOT EXISTS(SELECT 1 FROM native_installation_key_retirements r
  WHERE r.credential_id=n.credential_id AND r.pair_binding=n.pair_binding)
 AND NOT EXISTS(SELECT 1 FROM native_installation_consent_withdrawals w
  WHERE w.credential_id=n.credential_id AND w.pair_binding=n.pair_binding AND w.through_revision>=n.consent_revision);
DROP VIEW surface_push_live_capabilities;
CREATE VIEW surface_push_live_capabilities AS
 SELECT c.* FROM surface_push_capabilities c JOIN surface_push_delegations d ON
 c.delegation_id=d.id AND c.delegation_revision=d.revision AND d.revoked_at IS NULL AND
 c.revoked_at IS NULL AND c.expires_at<=d.expires_at AND
 c.install_id=d.install_id AND c.device_binding=d.device_binding AND c.owner_binding=d.owner_binding AND
 c.binding_id=d.binding_id AND c.grant_binding=d.grant_binding AND c.source_binding=d.source_binding AND c.scope_digest=d.scope_digest AND
 c.role=json_extract(d.policy_json,'$.token_role') AND c.platform=json_extract(d.policy_json,'$.platform') AND
 c.environment=json_extract(d.policy_json,'$.apns_environment') AND
 c.parent_bundle=json_extract(d.policy_json,'$.target.app_bundle_id') AND
 c.extension_bundle=COALESCE(json_extract(d.policy_json,'$.target.extension_bundle_id'),'') AND
 c.widget_kind=COALESCE(json_extract(d.policy_json,'$.target.widget_kind'),'') AND
 c.attributes_type=COALESCE(json_extract(d.policy_json,'$.target.attributes_type'),'') AND
 c.activity_profile=COALESCE(json_extract(d.policy_json,'$.activity_profile'),'') AND
 c.external_content_allowed=json_extract(d.policy_json,'$.external_content_allowed') AND
 c.max_operations<=json_extract(d.policy_json,'$.max_operations') AND
 c.max_events<=json_extract(d.policy_json,'$.max_events')
 AND (NOT EXISTS(SELECT 1 FROM native_installation_surface_bindings n WHERE n.delegation_id=d.id)
  OR EXISTS(SELECT 1 FROM native_installation_live_delegations n WHERE n.id=d.id));
CREATE TRIGGER native_surface_pair_retired AFTER INSERT ON native_installation_key_retirements BEGIN
 UPDATE surface_push_delegations SET revoked_at=COALESCE(revoked_at,CAST(unixepoch('subsec')*1000 AS INTEGER))
 WHERE id IN(SELECT n.delegation_id FROM native_installation_surface_bindings n WHERE n.credential_id=NEW.credential_id AND n.pair_binding=NEW.pair_binding);
END;
CREATE TRIGGER native_surface_consent_off AFTER INSERT ON native_installation_consent_withdrawals BEGIN
 UPDATE surface_push_delegations SET revoked_at=COALESCE(revoked_at,CAST(unixepoch('subsec')*1000 AS INTEGER))
 WHERE id IN(SELECT n.delegation_id FROM native_installation_surface_bindings n WHERE n.credential_id=NEW.credential_id AND n.pair_binding=NEW.pair_binding AND n.consent_revision<=NEW.through_revision);
END;
CREATE TRIGGER native_surface_consent_off_advanced AFTER UPDATE OF through_revision ON native_installation_consent_withdrawals BEGIN
 UPDATE surface_push_delegations SET revoked_at=COALESCE(revoked_at,CAST(unixepoch('subsec')*1000 AS INTEGER))
 WHERE id IN(SELECT n.delegation_id FROM native_installation_surface_bindings n WHERE n.credential_id=NEW.credential_id AND n.pair_binding=NEW.pair_binding AND n.consent_revision<=NEW.through_revision);
END;
CREATE TRIGGER native_surface_credential_deleted AFTER DELETE ON install_tokens BEGIN
 UPDATE surface_push_delegations SET revoked_at=COALESCE(revoked_at,CAST(unixepoch('subsec')*1000 AS INTEGER))
 WHERE id IN(SELECT n.delegation_id FROM native_installation_surface_bindings n WHERE n.credential_id=OLD.id);
END;
CREATE TRIGGER native_surface_credential_changed AFTER UPDATE OF id,token_hash,ha_install_id,disabled ON install_tokens BEGIN
 UPDATE surface_push_delegations SET revoked_at=COALESCE(revoked_at,CAST(unixepoch('subsec')*1000 AS INTEGER))
 WHERE id IN(SELECT n.delegation_id FROM native_installation_surface_bindings n WHERE n.credential_id=OLD.id AND (NEW.id<>OLD.id OR NEW.token_hash<>OLD.token_hash OR NEW.ha_install_id<>OLD.ha_install_id OR NEW.disabled<>0));
END;
CREATE TRIGGER native_surface_key_changed AFTER UPDATE OF receipt,key_spki,retired ON native_installation_first_key BEGIN
 UPDATE surface_push_delegations SET revoked_at=COALESCE(revoked_at,CAST(unixepoch('subsec')*1000 AS INTEGER))
 WHERE id IN(SELECT n.delegation_id FROM native_installation_surface_bindings n WHERE n.credential_id=OLD.credential_id AND n.native_operation_id=OLD.operation_id AND (NEW.receipt IS NOT OLD.receipt OR NEW.key_spki IS NOT OLD.key_spki OR NEW.retired<>0));
END;
CREATE TRIGGER native_surface_key_deleted AFTER DELETE ON native_installation_first_key BEGIN
 UPDATE surface_push_delegations SET revoked_at=COALESCE(revoked_at,CAST(unixepoch('subsec')*1000 AS INTEGER))
 WHERE id IN(SELECT n.delegation_id FROM native_installation_surface_bindings n WHERE n.credential_id=OLD.credential_id AND n.native_operation_id=OLD.operation_id);
END;
CREATE TRIGGER native_surface_publication_changed AFTER UPDATE ON native_installation_pair_publications BEGIN
 UPDATE surface_push_delegations SET revoked_at=COALESCE(revoked_at,CAST(unixepoch('subsec')*1000 AS INTEGER))
 WHERE id IN(SELECT n.delegation_id FROM native_installation_surface_bindings n WHERE n.credential_id=OLD.credential_id AND n.native_operation_id=OLD.operation_id AND (NEW.pairing_generation<>OLD.pairing_generation OR NEW.pair_binding<>OLD.pair_binding OR NEW.owner_binding<>OLD.owner_binding OR NEW.device_binding<>OLD.device_binding OR NEW.core_key_thumbprint<>OLD.core_key_thumbprint OR NEW.request_expires_at_ms<>OLD.request_expires_at_ms OR NEW.consent_revision<>OLD.consent_revision));
END;
CREATE TRIGGER native_surface_publication_deleted AFTER DELETE ON native_installation_pair_publications BEGIN
 UPDATE surface_push_delegations SET revoked_at=COALESCE(revoked_at,CAST(unixepoch('subsec')*1000 AS INTEGER))
 WHERE id IN(SELECT n.delegation_id FROM native_installation_surface_bindings n WHERE n.credential_id=OLD.credential_id AND n.native_operation_id=OLD.operation_id);
END;

CREATE VIEW native_installation_historical_capabilities AS
 SELECT c.* FROM surface_push_capabilities c JOIN native_installation_surface_bindings n ON n.delegation_id=c.delegation_id
 JOIN surface_push_delegations d ON
 c.delegation_id=d.id AND c.delegation_revision=d.revision AND
 c.expires_at<=d.expires_at AND
 c.install_id=d.install_id AND c.device_binding=d.device_binding AND c.owner_binding=d.owner_binding AND
 c.binding_id=d.binding_id AND c.grant_binding=d.grant_binding AND c.source_binding=d.source_binding AND c.scope_digest=d.scope_digest AND
 c.role=json_extract(d.policy_json,'$.token_role') AND c.platform=json_extract(d.policy_json,'$.platform') AND
 c.environment=json_extract(d.policy_json,'$.apns_environment') AND
 c.parent_bundle=json_extract(d.policy_json,'$.target.app_bundle_id') AND
 c.extension_bundle=COALESCE(json_extract(d.policy_json,'$.target.extension_bundle_id'),'') AND
 c.widget_kind=COALESCE(json_extract(d.policy_json,'$.target.widget_kind'),'') AND
 c.attributes_type=COALESCE(json_extract(d.policy_json,'$.target.attributes_type'),'') AND
 c.activity_profile=COALESCE(json_extract(d.policy_json,'$.activity_profile'),'') AND
 c.external_content_allowed=json_extract(d.policy_json,'$.external_content_allowed') AND
 c.max_operations<=json_extract(d.policy_json,'$.max_operations') AND
 c.max_events<=json_extract(d.policy_json,'$.max_events') AND n.scope_digest=d.scope_digest;
CREATE TRIGGER native_surface_scrub_revoked_targets AFTER UPDATE OF revoked_at ON surface_push_delegations
WHEN NEW.revoked_at IS NOT NULL AND EXISTS(SELECT 1 FROM native_installation_surface_bindings WHERE delegation_id=NEW.id)
BEGIN
 UPDATE surface_push_targets SET state='revoked',ciphertext=NULL,nonce=NULL WHERE capability_id IN
  (SELECT id FROM surface_push_capabilities WHERE delegation_id=NEW.id);
END;
