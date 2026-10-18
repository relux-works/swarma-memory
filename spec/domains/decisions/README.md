# Architecture-decision domain

The canonical documents are decision.json, rule.json and assumption.json. The
additional decision_proposal.json makes unreceipted proposals explicit instead of
coercing their statement kind. Each document satisfies the kernel domain
meta-schema and is referenced by exact id/version. All equality is literal typed
field equality; none of the schemas parses prose or grants action authority.

| Schema | Kind | Cardinality | Meaning |
| --- | --- | --- | --- |
| decision | decision_record | single, slot `[]` | Currentness follows canonical authority-receipt predecessor order; no freshness horizon |
| rule | fact | single, slot `[]` | A scoped rule statement; unequal overlapping values in one perspective are explicit incompatibilities |
| assumption | fact | multi, slot `[]` plus assertion id | Independently registered assumptions; no inference from unregistered prose dependencies |
| decision_proposal | proposal | multi | A proposed decision, without adopted status or deterministic proposal conflict |

`fixture.json` is a complete already-admitted snapshot and exact query. It uses
synthetic source objects and opaque receipts: version 1 says archive_home, version
2 says delete_home, and the second authority receipt succeeds the first. The
registered assumption rec:dependent has a review_on_change edge to the old
version and is dirty. Expected behavior is pinned by B01's direct-successor capture: cite the new decision,
retain the old version as historical, and flag that registered dependent. The
fixture is deliberately small; it does not pretend to measure usefulness.
B01 also refuses missing, prior, identical and incomparable replacement receipts,
then accepts direct and transitive successors. Successful exact replay survives
a later head; a new stale-CAS request conflicts. The reusable fixture retains
the original two-version case. S28/S29 cover ambiguous authority replacements
and late-arriving old decisions; ordinary incomparable canonical import remains
permitted without a memory-side replacement relation.

The domain admits only non-sensitive material suitable for a public project
description. No personal data, raw conversations, credentials,
private links or source payloads requiring physical erasure belong in its
versioned register. Sources needing retained excerpts require their own admission.
The domain schema does not make an external decision current by itself.

The profile documents' `requirements` are declarative restrictions, not executable
callbacks. `authority_receipt_for_current` is implemented by K-REV-3; no policy
selection or check execution occurs inside a schema. A decision proposal can
become a decision_record only through a separately admitted authority receipt and
properly typed assertion; a proposal revision cannot silently change schema kind.
