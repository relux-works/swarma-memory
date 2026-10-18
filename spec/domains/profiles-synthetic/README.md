# Synthetic profile domain

All subjects, places, accounts and source objects in this package are invented.
The schema documents and fixtures authorize no real personal admission. Real
profiles require the separate protected-service qualification and owner policy.

| Schema | Cardinality | Freshness default | Constraint |
| --- | --- | --- | --- |
| interest | multi | none | Distinct values coexist; self-description is not an observer hypothesis |
| competence | multi | none | Self-assessment is not established competence |
| location | single per kind | 7 days | Value is sensitive and private by default; kind identifies residence/current/work area without kernel-specific interpretation |
| availability | single | 1 day | Expiry means refresh needed, never false |
| intent | multi | 7 days | A stated intent is not a commitment or consent |
| account_link | multi | none | More than a claim requires an exact account_control assessment |
| relationship_status | single | none | No rule derives consent or openness to introductions |
| open_to_introductions | single | none | Separate enabled and adult_opt_in statements; not permission to disclose contact details |
| interest_hypothesis | multi | none | Explicit proposal schema for an observer's model |
| location_city | single | 7 days | Coarse output schema; private-coordinate derivation still needs exact owner declassification |

Every domain schema supplies exact field types/equality, statement kind, slot
fields, incompatibilities, freshness default and class-based disclosure defaults.
String values are exact synthetic identifiers/text; no geocoding, intent parsing,
natural-language equivalence or location precision inference is performed.
Only a pinned transformation's already approved output can be declassified.

The `requirements` labels do not install kernel inference rules. `synthetic_only`
restricts this package's authorized corpus. `account_control_for_established`
requires the consumer to retain the exact account_control assessment if it makes
that stronger claim; an ordinary self-declaration view remains attributed data.
`no_derived_consent` forbids automatic consent inference. `adult_opt_in`,
`mutual_contact_consent` and `mutual_partner_confirmation` bind later domain
services: romantic introductions need explicit adult opt-in, contact details need
mutual consent, and a public partner link needs both parties' confirmation.
The kernel stores evidence of those statements but executes none of those actions.
An enabled statement with adult_opt_in false may be stored as attributed data;
it cannot authorize a romantic introduction. The schemas deliberately include no
matching, catalog, contact or relationship-action operation.

P01–P15 supply the complete embedded synthetic snapshots. P01/P03 keep observer
assertions distinct from self-description; P02/P10 exercise representation and
concurrency; P04 pins expiry; P05 releases only a city; P06 rechecks send rights;
P07 preserves one root across three carriers; P08 erases controlled derivatives;
P09 separates public handles; P11 preserves private lineage restrictions.
