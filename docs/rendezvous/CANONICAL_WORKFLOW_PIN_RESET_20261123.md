# Canonical reusable workflow history reset

The old shared-workflows commit `4025a68add8ba98f1f2e0307d7f3998e45c0d9ef`
no longer shares ancestry with canonical `main`. The unchanged API ancestry guard
therefore stops validation before product tests. The replacement pin is canonical
`ef8fe39c66689822887fee3720c7500eaa76955a` in repository
`djconnect-music-dj/djconnect-shared-workflows` (repository ID `1461346322`).

All five consumed workflow blobs have identical Git blob IDs at both pins. The
new immutable `api-canonical-workflow-pin-reset-v1.json` records those identities,
20 exact caller transformations (22 `uses` references), and ten active manifest
hash refreshes. This is not a claim that the entire shared repository is equal:
two unconsumed `*-ebbb.yml` workflows differ.

Historical delta files remain unchanged. Independent Python and JavaScript
validators first verify the new delta's fixed digest, closed paths and exact
current bytes, then reconstruct the historically qualified inputs. Current
preparation and active manifests bind the new bytes. Both activation flags stay
false; all 22 preparation gates stay open. Neither validator authorizes release,
installation or deployment. The ancestry guard and workflow permissions, jobs,
thresholds and product sources are unchanged.

The existing mandatory qualification entrypoints include reset tampering checks.
They reject modified workflows/manifests and a modified delta. Guard regression
continues to check missing workflows, noncanonical commits and lookup failures.

This repair is separate from guest-boundary PR #275. It requires its own review,
publication authorization and normal merge gates. No unchanged Worker redeploy is
needed for either source-only increment.
