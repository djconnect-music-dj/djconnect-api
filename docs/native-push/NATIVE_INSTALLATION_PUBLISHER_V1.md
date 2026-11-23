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

## Selected limited development admission

The platform owner selected `ios-native-push-development-40532/1`, expiring
2026-12-23T10:00:00Z, for the actually signed iOS artifact with application ID
`ZEML4LPXH4.dev.djconnect.ios`, bundle build `40532` and App Attest environment
`development`. The server admits launch-validation category 3 (`AwAAAA==`) as
an explicit policy choice, not a claim that Apple has already attested it.
Actual Apple evidence must prove this exact tuple before any registration ACK.
A later build requires an independently selected new policy, never a wildcard.
All shorter original source, request and channel expiries remain bounded by
minimum; the policy window does not renew them. This is configuration selection,
not native/provider or physical acceptance.

## Original pair partition and negative custody

The platform owner selected private key partitions derived from the actual
origin, installation ID and **original committed PairJournal registration
binding**. Only that actual current journal object supplies the binding; no
request field selects a partition. Each genuine ordinary device pair has its
own key custody. This is not an installation-global signing key shared between
credentials. Rotation within the same original pair still mismatches its
original custody and never generates a replacement automatically. A fresh pair
requires its own genuinely committed pairing and explicit new channel opt-in.

After a genuine own-publication ACK, Core commits and reads back private atomic
negative-only credential custody before returning any native key challenge.
The existing original SQLite pair-retirement journal may use that exact
publication/credential to withdraw or retire after unpair or restart. This is
necessary when the original ConfigEntry has been removed. This private record
never supplies the positive enrollment path, an original pair, a registered-key
winner, a native clock or a Widget permission. Other pair/operation/field
combinations are denied. Revoked or rotated credentials remain denied by the
server's original ID/hash check; no replacement principal is adopted. The
negative writer retains its lock through an actual pending atomic write even
if the requesting task is cancelled. Private tokens are never exported.
