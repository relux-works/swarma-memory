# Authorized read evaluation

`State.Read(query)` accepts the complete closed query schema and returns a
complete view or one typed refusal. `Recall`, `Explain` and `Changes` implement
the `Kernel` interface through this same path. `Query`, `View`, `VersionRef`,
`Bounds`, `Cursor`, `Explanation` and `ChangeSet` carry decoded JSON values
(`int64` integers). For `Explain` and `Changes`, `Context.ReadQuery` supplies the
full pinned query; their explicit target/cursor and bounds replace those fields.
A nonempty `Context.Actor` supplies the authenticated principal. These methods
return the complete view, preserving both extended polarity records.

`State.Capture(operationIndex, query)` saves an immutable, detached view and its
protected binding. `Captured(index)` returns another detached copy of those
historical bytes. Captures are adapter/session state, not semantic records or
public cursors. They are not serialized by the storage `Snapshot` API. The
conformance adapter assigns capture indexes from operation positions.

## Validation and visibility

Reads validate closed JSON shape and nonnegative bounds, public schema and rule
lookup, policy/evidence pins, predeclared availability and restore gates before
filtering records or evaluating evidence. Exact committed memory boundaries and
the complete admitted source frontier are required. Supplied timestamps use real
UTC calendar seconds; `valid_at: any` includes unknown validity. Freshness uses
only the supplied consumption clock.

Filtering requires read, use, metadata, audience, purpose, space, subject,
perspective, context, validity and knowledge cut. Source references retain their
own provenance/perspective: they are data associated with an assertion, not an
assertion literal that changes the selected issuer perspective. Hidden roots,
premises, named sources and certificates cannot spend logical budget or produce
public gaps. Unauthorized revisions cannot change visible currentness. Owner
exclusions affect selection and historical/review metadata, while authorized
premise use remains possible.

Ordinary heads follow eligible revision links. Decision heads use canonical
receipt maxima in the deciding issuer's restricted graph, including intermediate
events with no assertion. Incomparable maxima remain sorted `ambiguous_current`
items. This neither creates opposition nor changes a refused write's
`version_conflict`. Incompatibility is a separate symmetric domain relation over
authorized current assertions with known overlapping intervals.

## Bounded evidence

Each displayed assertion and polarity gets an independent depth-first walk.
Roots precede rules, both sorted by reference; AND premises sort by exact
assertion reference and polarity (oppose first). Each walk memoizes literals,
visits all premises and alternatives, and resolves each distinct current-required
source once. Effective limits are the component-wise minimum of requested and
policy bounds. Zero is valid; eligible skipped work produces explicit sorted
cutoffs and incomplete enumeration. A successful path survives incomplete
alternative enumeration.

Proof paths retain root/justification references, qualifications, deduplicated
origins, necessary signed premises and the weakest necessary source state.
Alternative paths choose the strongest complete source state. Independent
opposite searches determine premise quality without spending the conclusion's
existence counters. One clean path wins; otherwise complete enumeration of only
tainted paths yields `conflicted_premises_only`. No witness never claims corpus
absence. Coverage declarations must be unique and authorized.

`explain` sorts and deduplicates proof paths, then applies the explanation cap.
Proof truncation does not truncate evidence; incomplete evaluation and proof
truncation have separate reasons. `recall` has an empty complete explanation.
Compact rendering preserves all polarity fields. Calendar arithmetic adds schema
freshness durations without reading a clock or loading timezone data.

Dirty effects require a retained, visible cause and an eligible registered path
immediately before that revision. Hidden causes leave the public graph unchanged.
Reads clear no global dirtiness. A supplied recomputed snapshot with cleared
causes does not recreate them from historical revisions. Review metadata is
anchored to the selected assertions or registered dependents of their sequences;
those dependents may have other schemas.

`changes` requires a matching earlier capture binding (principal, purpose,
audience, space, subject, schema and projection rule). It compares visible
content, qualification, currentness and authorization metadata, excluding fresh
handles and proof-rendering choices. Removed items can produce `changed` with
no currently authorized reference. Frozen results are never rewritten by these
comparisons or a later freshness clock.

## Handles and boundary minimum

The adapter supplies fresh uniform 128-bit handles; the conformance adapter uses
`crypto/rand`. The kernel validates their 32-character lowercase hex encoding and
rejects reuse, including collision with imported replay receipts. All occurrences
inside a view share the view handle. Successful write replay preserves its prior
receipt. The kernel performs no entropy, clock, filesystem, network or process IO.

The read task needs these limited neighboring semantics:

- K-DISC-1, P13: audience projections filter unknown lineage, including unknown
  transitive inputs; existing admitted disclosure constraints still apply.
- K-DISC-3, P07/S30: admitted root origins are deduplicated, not counted per copy.
- K-DISC-4 and the audience shape in K-DISC-2, P09/P15: exact policy aliases apply
  independently to subject, issuer, submitter and perspective principal. Missing
  aliases refuse; internal references, proof vertices and root ids are redacted.
- K-PUB-2, B03/S23/P07: associated publication sources distinguish a checked
  current import from `last_received`; a mirror report alone stays an issuer
  statement. No delivery or current authorization capability is created.
- K-ERASE/K-SNAP: initial erased source state and restore fences are honored;
  retained/independent assessments remain distinguishable from fresh resolution.
  Erasure, restore and delivery operations themselves remain unsupported.

`SetAvailability` is only an owner harness stimulus under a predeclared
`coarse_unavailable` policy. It changes the admitted coarse availability state,
returns an `availability_changed` receipt and advances no semantic cut. Load
continues to change only protected hidden work. Neither is a kernel execution
capability. Physical resource isolation and deployment qualification remain
adapter/deployment obligations.

## Measurement and validation

All 56 read-task target vectors pass whole; all are required in
`conformance/passing.txt`. The other ten need operations outside this task:
B07, P05, P06, P08, P11, P12, S20, S24, S25 and S26. They remain failures rather
than fabricated effects of unsupported disclosure/erasure operations. Admission
agreement remains 70/73 raw (70/70 in scope), required by `passing-ops.txt`.
The CLI reports 56/66 and exits 1 until all semantic vectors pass.

Tests cover input permutations, zero/clamped budgets, hidden dependencies and
metadata gates, three distinct conflict outcomes, exact freshness boundaries,
frozen bytes, current capture bindings, dirty causes/private controls, source
AND/OR aggregation, assessment pins/expiry/context, output ownership,
configuration ambiguity and malformed/reused handles. Corpus comparator oracle
and mutation controls remain unchanged. Run from the repository root:

```sh
go vet ./...
go test ./...
go test -race ./kernel -run 'TestRead|TestHidden|TestDirtyProjection|TestFrozen|TestAvailability|TestTyped|TestThreeConflict|TestSourceAndPremise|TestChanges'
python3 -B spec/checks/validate.py
go run ./cmd/memory conformance
```

The structural checker is not an evidence evaluator. Logs and task notes belong
under ignored `.temp/`; no alternative evaluator is used by this implementation.
