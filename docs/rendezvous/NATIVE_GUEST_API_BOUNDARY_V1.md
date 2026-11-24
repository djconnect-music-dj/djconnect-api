# Native guest mode: API boundary and integration scenarios

This records the API slice of the 23 November Apple/VibeCast improvements,
especially points 11, 22 and 23. DJConnect Core remains product and guest
authority. This change adds integration regressions; it changes no Worker
runtime, configuration, migration, native policy or deployed artifact.

## Ownership

- Apple owns the actual Google Cast sender and native joined-session UI.
- The receiver owns the content-free `https://vibecast.tv/join` app-opening /
  installation landing. V1 supplies no interactive mobile guest website.
- Core's existing `/api/djconnect/v1/participation/` issuer owns invitations,
  redemption, renewal, withdrawal, public context, isolated temporary guest
  questions, requests and host policy. Extend that boundary when needed;
  do not introduce a second central guest engine or expose host credentials.
- API rendezvous is the existing paired-native-to-screen destination handoff.
  It is not guest admission, a rich Session proxy or a source of playback
  authority. A Core guest invitation/bearer cannot replace its native proof.

The guest invitation's rotation and the guest lease remain separate from the
owner/screen rendezvous transaction and its release-policy window. In particular,
the API's two-hour bounded trial window is not the VibeCast share lifetime.
Changing share duration does not justify extending native admission.

## Golden negative integration scenarios

`test/vibecast-guest-boundary.spec.ts` exercises the shipping Worker and local
D1 diagnostic storage with synthetic guest inputs:

1. Core participation requests are not silently handled or proxied by the
   central API. Unknown routes do not read the guest request body. Diagnostics
   contain only the existing fixed unmatched route/status, not the invitation,
   bearer, query value or guest's question.
2. Guest inputs cannot open native endpoints without the existing edge and
   release-policy admission. These denials do not retain the private input or
   call external providers.
3. With fixed local edge/policy fixtures, a guest bearer is rejected before
   reading its body. Removing that bearer does not turn a guest invitation
   into a native attestation, submit challenge or submission payload.

All scenarios forbid egress. The local edge/policy values are fixtures, not
proof of actual Cloudflare provenance, App Attest or physical iPhone/TV behavior.
The existing rendezvous-composition suite separately retains positive browser
creation and the exact 120-second transaction checks, plus negative gates.

Run with the exact locked dependencies and an external temporary directory:

```sh
npm test -- --run
npm run test:rendezvous-composition
npm run test:rendezvous-product
npx tsc --noEmit
```

These are software/contract checks. Real app-link handling, signed-app launch,
post-install invitation recovery, real guest isolation and Cast receiver
acceptance require the owning Apple/Core/receiver qualification. A passing
central API suite cannot establish those outcomes.

## Deployment

There is no runtime change to deploy for this API slice. Do not redeploy an
unchanged Worker merely to mark this improvement complete. A later necessary
API runtime change still requires the exact normal qualified artifact, central
operational manifest, protected deployment and independently read-back rollback
and health identities. Test fixtures do not loosen those requirements.
