# Automatic installation publisher and first trust

Selected 23 November 2026 by the platform owner: the existing **active API
credential ID and token hash** may authenticate the installation's own Core
pair/consent publisher. A caller-supplied HA installation ID never selects,
recovers or adopts a principal. Two valid credentials naming the same HA ID
remain different principals. This is distinct from the preproduction CF Access
machine publisher, whose routes, schema, policy and admission remain unchanged.

The production port consists of authenticated, canonical JSON POST operations:

- `/v1/push/native/installation/resolve`: `{contract_version:1}` resolves only
  the current bearer to its existing credential ID and recorded HA install ID.
  This read creates no key, pair publication, principal enrollment or policy.
- `/v1/push/native/installation/publisher/operation`: the existing first-key
  publication fields (contract_version, install_credential_id, operation_id,
  pairing_generation, pair_binding, owner_binding, device_binding,
  core_key_thumbprint, request_expires_at_ms, consent_revision).
- `/v1/push/native/installation/publisher/withdraw`: contract_version,
  pair_binding and consent_revision. A monotonically retained own-principal
  tombstone fences queued equal/older consent before any remote side effect.

The bearer must resolve to a genuine active `install_tokens` row. Every write
and first-key decision rechecks the original ID AND token hash AND active state
in the same SQL statement. Rotation/revocation during an awaited operation
cannot commit from the earlier authentication result. The publication's
install_credential_id must equal that authenticated ID. There is no caller
principal override, alternate HA-ID lookup, CF identity coercion or fallback.
Own-principal publication is DATA; it never supplies a registered key receipt,
App Attest result, WidgetIssuerOwner, target permission or native admission.

Core uses its actual already-loaded ordinary installation bearer/origin and
persisted original ConfigEntry, not a newly generated widget install token.
Before publishing an operation, it requires its original `capture_pair` and
PairJournal acknowledgement, persisted device/Profile/source, current explicit
SQLite channel consent and original signer. The existing first-key request
currentness, original deadlines, one-shot decision and request hash remain.
Resolve only returns metadata; the token stays in Core custody. No synthetic
fixture or caller boolean may stand in for any original Core check.

Production first trust retains the actual challenge, P-256 proof and Apple App
Attest verification chain. Its trusted server composition selects the genuine
signed app identifier, build, App Attest environment, launch policy and policy
expiry. Absent/unknown signing policy is unavailable. It does not infer App
Attest environment from an APNs token or accept a client-selected policy.
Production uses the explicit `djc-native-push/1` audience; the existing
`djc-native-push-ha-dev/1` remains confined to its existing composition.

Production state is separate from HA-dev qualification tables. Pair retirement,
withdrawals, unique registered-key constraints and operation decisions include
the authenticating credential ID, not only opaque pair hashes. Reusing another
principal's HA ID, pair hash, operation ID or public key cannot read, adopt,
retire or block that principal's original registration. Neither a resolve nor
publication automatically enrolls a principal. Only a genuine verified native
registration winner may produce the separate sealed RAM handoff.

Widget delegation, target, field policy, original clock, native SDK enrollment
and provider/device acceptance remain separate requirements. This port does
not turn on an empty surface profile, reuse HostWake as Widget authority or
change independent Watch/Live Activities/Moments consent. All failure responses
are content-free and no-store. Bearers, private keys and provider secrets never
enter diagnostic records or qualification artifacts.
