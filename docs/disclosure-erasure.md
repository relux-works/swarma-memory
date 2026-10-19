# Disclosure, publication and erasure model

Stage 1 implements all 66 semantic vectors using the public normative package.
`State.Write` accepts `declassify`, `revoke_declassification`, `revoke`, `deliver`,
`erase`, `restore` and `reconcile_restore`, alongside admission and revision.
The finite `control` and `request_check` stimuli record an external observation
or return `execution_required` as data; they execute nothing.

## Disclosure and prepared delivery

Known content lineage constrains every new read and every write. Audience and
purpose labels intersect through all known inputs, field classes union, and the
earliest retention deadline survives. Incomplete lineage retains its known lower
bound and cannot enter an audience projection. Logical premises do not invent
content inputs or grant read, retention or forwarding rights.

Declassification atomically admits the owner assessments in proposal order,
followed by the output assertion. Each assessment must authenticate identical
complete direct inputs, transformation, output schema, `DigestJSON(output.body)`,
audience/purpose and current policy/environment pins against an active protected
owner decision. The body digest precedes envelope stamping. Owner coverage walks
the transitive input closure, including field defaults. Retention and fences are
never widened. Evidence records may have a different issuer from the submitting
representative; the self-declaration identity constraint applies to assertions.

New disclosure rechecks decisions, evidence completeness, expiry and disposition.
Every cited assessment must remain active under current protected revision state,
including revisions hidden from the reader and reads at an older transaction cut.
Withdrawal, replacement and correction retire the exact cited version; a valid
new version cannot silently replace that citation. Challenges preserve it.
Revoking a decision leaves history intact and restores ordinary inherited
constraints. The release permits only its exact audience/purpose pair. Audience
items use admitted per-audience aliases and redact internal refs, source/proof
vertices, representation references, authority receipts and root identifiers.
Independent origin counting remains separate from copying or release evidence.

`Capture` saves a detached view and a protected binding to its exact selected
versions. `deliver` requires that audience projection's actor, audience and
purpose, then rechecks current policy, read/use/forward rights, disclosure,
freshness, issuer/import currentness and erasure fences. It never substitutes a
new selection or context. Revoked disclosure yields `disclosure_revoked`; stale,
replaced or unchecked imported publications yield `publication_stale`. Known
replacement is historical; an unconfirmed import is `last_received`. Frozen
results grant no current authority. Delivery returns a receipt and performs no
external publication or control effect.

## Erasure, replay and restore

Erase computes the transitive content-record closure and every affected custody
sink independently of reasoning edges. It records fences/obligations and advances
disposition generation before another semantic write/read can acquire the state
lock. Only reachable controlled sinks named in the requested boundary are
accounted as purged. Missing/unreachable controlled sinks produce an `incomplete`
receipt with `purge_pending`, keeping access closed. Independent recipients are
never counted as purged. A later key may complete an incomplete attempt.

Receipt refs are the pre-fence metadata-authorized subset for the authenticated
actor's exact receipt context, with current read/use/metadata and disclosure
constraints. Omitted refs remain fully fenced and included in custody accounting.
Erase authority alone does not disclose them. Canonical erase intent includes
the entire receipt context, excluding only intake time and key. Exact replay
rechecks every stored receipt ref, returning the original receipt unchanged;
loss of metadata authority refuses `not_authorized` without regenerating it.
An authorized changed context under the same key is `idempotency_conflict`.

Per-record fences omit payloads before selection without an existence-revealing
refusal; separately authorized source headers can remain with erased availability.
Old-generation writers get `stale_generation`; a current-generation derivative
of erased input gets `erasure_fenced`. Restore-wide fencing refuses reads and
writes. The supplied initial snapshot is the fixture backup: restore brings its
custody presence back behind the fence while retaining current authority,
disposition generation and obligations. Reconciliation requires current complete
outside-domain evidence, coverage of all obligations and reachable affected
controlled sinks; it reapplies fences and purges before reopening access.
Unwitnessed or incomplete reconciliation refuses `erasure_incomplete` atomically.

The snapshot is a protected **semantic model**, including admitted reference
inventory and replay history. `Snapshot` and `Captured` are trusted adapter/test
storage interfaces, not authorized disclosure APIs. Custody presence flags and
receipts express admitted fixture dispositions; this in-memory implementation
does not perform secure deletion, durable fencing, backup restoration or external
witness verification. Those need the eight protected-deployment vectors and a
real adapter. Semantic agreement is not deployment qualification.

## Validation

Run from the repository root:

```sh
go -C go vet ./...
go -C go test ./...
go -C go test -race ./kernel
python3 -B spec/checks/validate.py
go -C go run ./cmd/memory conformance
```

All 66 whole vectors, 73 admission operations, boundary operations and six
inventories match. Both ratchets are full; CI conformance is mandatory.
Tests retain mismatched-pin and revoked/fenced-evidence witnesses, admitted
assessment withdrawal/replacement/correction with challenge controls, transitive
taint with a public control, hidden-record removal properties across corpus
reads, custody/replay/restore/generation controls and instruction-like text
delivered only as data. The noninterference property preserves public cuts,
policy and availability, removes hidden reference dependents to keep paired
snapshots valid, and explicitly excludes removals that change authorized
assertion inputs (including independent releases). It compares normalized views
including changes and exact refusal choices. Structural checks and comparator
mutation plants establish their own detection controls, not physical isolation.
All optional logs and probes belong under ignored `.temp/`.
