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

After a genuine resolver response and exact durable SQLite staging, Core commits
and reads back private atomic negative-only credential custody before sending
the publication RPC or returning any native key challenge.
The existing original SQLite pair-retirement journal may use that exact
publication/credential to withdraw or retire after unpair or restart. This is
necessary when the original ConfigEntry has been removed. This private record
never supplies the positive enrollment path, an original pair, a registered-key
winner, a native clock or a Widget permission. Other pair/operation/field
combinations are denied. Revoked or rotated credentials remain denied by the
server's original ID/hash check; no replacement principal is adopted. The
negative writer retains its lock through an actual pending atomic write even
if the requesting task is cancelled. Private tokens are never exported.

## Signed Widget delegation and role acknowledgement

`POST /v1/push/native/installation/issuer/enrol` accepts ordinary installation
bearer authentication and canonical JSON with exactly `contract_version:1`,
`first_key_receipt`, `delegation` and `signature`. `first_key_receipt` is the
exact registered-key ACK retained by the winning continuation. `delegation`
is the existing `djc-surface-issuer/1` Enrolment without field changes, as
specified by `surface_issuer_wire.py` / API `surface-push/issuer-wire.ts`.
The P-256 raw-64 signature is base64url without padding, over canonical JSON:

```
["djc-installation-surface-delegation/1", "POST",
 "/v1/push/native/installation/issuer/enrol", first_key_receipt, delegation]
```

The server requires its own active original credential ID/hash, the EXACT
matching registered native first-key row/receipt, and the original pair
publication/consent at commit. Initial enrol must occur within the first-key
winning window. It verifies the signature with that row's original SPKI and
cryptographically compares its public coordinates with `delegation.public_key`.
Surface key thumbprints and native SPKI digests remain different namespaces.
`approval_reference` equals the actual native registry generation and
`install_id` equals the actual native API installation ID. Only Widget policy,
null activity profile, no external content, and the explicitly selected actual
native target are eligible; no Watch/Live Activity alias or operator bypass.

A successful winner returns exactly:

- `contract_version:1`, `success:true`, `state:"enrolled"`, `replayed:false`;
- `delegation_id`, `delegation_revision:1`, `key_thumbprint`, `scope_digest`,
  `expires_at_ms` from the existing exact enrolled delegation;
- `enrol_operation_id`, `install_credential_id`, `native_operation_id`,
  `native_api_installation_id`, `native_registry_generation`;
- `enrolment_sha256`, SHA-256 of the exact canonical signing array above.

The existing `scope_digest` continues to bind all original Surface fields,
public key and exact policy. `expires_at_ms` is the accepted original
`policy.original_grant_expires_at_ms`, bounded by its actual Core role grant,
the existing maximum eight-hour policy and the selected server policy expiry.
It is NOT a 30-day native-key lifetime and does not renew the initial first-key
challenge. Replay, unknown, status and withdrawal cannot supply a winning ACK.

Only the original server-private first-key winning continuation can consume
that exact actual ACK into one new WidgetRoleKeyCustody. That distinct role
retains the same actual signer, pair, loaded credential and consent, with its
own original role expiry/clock mapping. The old first-key witness is consumed,
not extended. No raw signer, caller JSON constructor or restored status creates
role custody. Actual v4 read/v3 native-clock qualification remains separate.

## Live provenance after issuance

The initial selected Widget target is platform `ios`, app
`dev.djconnect.ios`, extension `dev.djconnect.ios.track-insight-widget`, kind
`DJConnectSessionWidget`; small/medium/large share that same kind. It is not a
Watch or Live Activity target. The original selected signed iOS build remains
40532 until a separately qualified policy selects a new actual signed build.

Every production delegation retains its authenticated credential ID/hash,
original native registry receipt, pair publication and consent revision. Live
lookups and same-statement commit authorization for issuer issue, capability
registration and provider dispatch must retain that provenance. Native pair
retirement, credential revocation/rotation and a covering consent withdrawal
close already issued delegations/capabilities, not merely subsequent enrolment.
Core v4 reads retain their own actual role/source/clock fences. No old operator
row is eligible through this production composition. Initial key challenge
expiry is not reused as the role lifetime; the original accepted role grant is
its own bound after the genuine winning transition.

After successful production enrolment, the existing signed Surface issuer
challenge/issue/status/withdraw wire and existing Surface registration,
status/revoke/event wire remain unchanged. Production composition admits only
records linked to genuine native-installation delegation provenance. Negative
status/withdraw/revoke retain their original scoped semantics after retirement;
they cannot mint a fresh role or provider effect. The generic surface compiled
closed gate, existing operator paths and activity-profile gates are unchanged.

The existing withdrawal wire retains the **original publication consent
revision**. Its negative authority is the separately committed SQLite off
revision greater than that publication, or the same original PairJournal row
already retired. It is never a fabricated higher wire revision. Genuine unpair
also queues an authenticated publisher withdrawal so both the original
withdrawal and retirement acknowledgements can be obtained. The bounded private
negative ledger may prune only after BOTH exact original journal ACK markers
are committed, with original event/body/origin/publisher/pair binding intact.
Pruning uses the same private writer lock and atomic readback. Time, status,
missing rows, a single ACK, malformed state or capacity pressure cannot discard
pending credentials or create a positive restore path.

## Negative-only unknown-outcome hardening

The selected private negative credential record is one per original committed
PairJournal registration binding plus actual credential, origin/installation
and exact native pair context. It is retained only after a genuine resolver
result and an exact durably staged SQLite original, **before** publication RPC.
It covers only matching actual SQL originals; it is never positive restoration,
a replacement credential, a fabricated publication ACK or a signing grant.
Operation digests are comparison metadata and cannot substitute for SQL rows.
The private format is version 2; older or malformed state is unavailable, never
silently migrated, reset or interpreted as a new positive installation.

For a negative unknown publication, the active authenticated original API
principal may set its own covering pair tombstone when that operation has no
publication row. If a row exists, all original fields must match. A permanent
retired pair remains closed to later positive publication, first trust and
roles. Negative closure is independent of positive signed-app-policy expiry.
The API budget counts at most 64 still positively admissible publications.
An authenticated covering withdrawal OR permanent own pair retirement excludes
that publication from the active budget; original history and all irreversible
positive fences remain unchanged. Negative closure is never blocked by that
positive-operation budget. This does not authorize private credential pruning.

Private custody is pruned only when **all** matching actual SQL originals and
all retained operation references have their exact genuine withdrawal and
retirement ACKs, with the original pair retired. Missing, mismatched, pending
or unknown rows remain. Grouping removes duplicate private tokens for repeated
operations without discarding their original proofs or minting any authority.


## Genuine Widget reauthorization — 24 November 2026

ON/OFF/ON does not repeat or reopen first trust. The original registered native
key remains unique for its original pair; permanent pair retirement is final.
The production first-key writer must retain the actual Apple verifier's key ID,
SPKI, zero counter, verified policy/category and evidence deadline atomically
with its winning native ACK. A boolean, fixture, old receipt/status or caller
key cannot produce this enrollment metadata. Original proof deadlines and the
selected signed-build policy remain upper bounds; assertions do not establish
a newly installed build.

The new own-principal role reauthorization paths are
`POST /v1/push/native/installation/issuer/reauthorize/challenge` and
`POST /v1/push/native/installation/issuer/reauthorize/register`.
They use the actual active installation bearer, not CF/operator authority.
Challenge input is exactly `{contract_version:1, first_key_receipt,
publication_operation_id, delegation, signature}`. Its raw P-256 signature is
over canonical JSON `["djc-installation-widget-reauthorization/1", "POST",
"/v1/push/native/installation/issuer/reauthorize/challenge",
first_key_receipt, publication_operation_id, delegation]`. The real original
Core key, exact original native ACK and a newly current original publication
with the same original pair/key context and current unwithdrawn consent revision
are required. Reauthorization after opt-out requires a strictly newer actual
consent revision. Existing immutable delegation IDs/once-issuance rules remain.

The server returns one fresh, once-only 32-byte nonce with a 120-second maximum
challenge deadline, bounded further by original current publication, selected
policy and actual verified native-key evidence. Its exact challenge object has
`contract_version:1`, `api_audience:"djc-native-push/1"`, `challenge_id`,
`challenge_nonce`, `expires_at_ms`, `publication_operation_id`,
`first_key_receipt_sha256` and `delegation_sha256`. Hashes compare exact saved
DATA; none is a substitute for original cryptographic authority.

Register input is exactly `{contract_version:1, challenge, first_key_receipt,
delegation, apple_proof:{kind:"assertion",key_id_b64,proof_b64}}`.
Apple App Attest receives SHA-256 of canonical UTF-8 JSON
`["djc-installation-widget-reauthorization/1", "POST",
"/v1/push/native/installation/issuer/reauthorize/register", challenge,
first_key_receipt, delegation]` as its clientDataHash. The server verifies the
actual fresh assertion with the originally enrolled actual Apple key, RP,
selected properties/category and a strictly increasing global per-key counter.
The existing assertion cryptographic kernel is shared; its existing HostWake
job/principal remains separate from this role's own actual SQL authority.

The private once claim is acquired before cryptographic awaits. Actual counter
CAS, exact new publication/consent/pair/credential guards, native provenance and
new immutable role insertion commit together. Only that winning execution gets
a new role ACK with the same fields as original issuer/enrol, bound to the new
publication and exact signed declaration. Its expiry is the actual declared
role grant bounded by the actual original source/consent/native evidence/policy;
no first-key nonce or existing role is extended. Unknown/replayed/status,
reentrant credential rotation, opt-out, bad proof and stale counters cannot
issue a new ACK, restore a consumed challenge or resurrect an old role.
