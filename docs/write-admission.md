# Write-side kernel

`kernel.NewState(snapshot, schemas, mint)` loads an admitted complete snapshot.
It checks the closed structural schema, exact references, lineage bindings,
identity bindings, sequence/cut invariants, ordinary single heads, authority DAG
integrity and dirty causes. Future proposal facts are protected intake evidence;
they do not make their named outputs present.

`State.Write` accepts decoded `admit`, `admit_raw`, `revise` and `declassify` transactions, plus the finite [disclosure/erasure boundary operations](disclosure-erasure.md).
`State.Admit` supplies the typed `Kernel` interface. `State.Snapshot` is a storage
adapter API returning a detached complete snapshot; it is not an authorized read
view. The kernel uses only standard-library computation and a mutex. The adapter
supplies a fresh-handle function; the conformance adapter uses 16 bytes from
`crypto/rand`. No kernel code reads a clock, filesystem, network or environment.

The transaction checks the entire hypothetical batch in K-API-2 class order:
shape/profile; current operation and retention rights; replay/conflict;
representation/review; erasure generation/fence; references, schemas, content,
time and context; revision authority/CAS; rule qualification/cycles; limits.
Within the record-validation class, field-name order determines the first
violation. Candidate stamping and disclosure derivation stay private until one
commit publishes records, the final transaction cut, replay receipt and dirty
causes. A refused batch leaves the complete stored snapshot unchanged.

The replay identity is actor, space and key. Canonical intent excludes the key
and intake time, retaining actor, class and the full retention context. Raw JSON
is parsed into the same admit intent. Current retention grants, revocations and
strict deadlines apply to outputs and their transitive known inputs before
replay/conflict. Exact successful replay preserves its original handle and
recorded time after head changes. Metadata and retention permissions remain
independent.

Ordinary revisions use admitted revision order as their CAS token. Replacements
preserve the sequence key and advance the same id by one version, with replacement
recorded before revision. Availability and withdrawal use the revision reference
as the next token. Challenges are attributed records and do not move the target
head. Authoritative decisions use eligible canonical receipt maxima. Strict
receipt succession searches the graph restricted to the deciding issuer before
reachability; foreign paths never create bypass edges. All-issuer intermediates
need no attached assertion. Equal, prior and incomparable replacement receipts
refuse with non-retryable `authority_receipt_required`.

Known content inputs resolve against the whole batch, independent of array
order. Incomplete facts preserve their known lower bound and `lineage: unknown`.
Disclosure taint intersects audience/purpose labels, unions field classes and
keeps the earliest deadline. Conflicting domain assertions remain separate
records: admission does not manufacture opposition or evidence. The [read evaluator](read-evaluation.md) computes deterministic
`incompatible_with` fields without creating signed evidence.

`SeedLoad` is the owner-only harness stimulus for `hidden_work`. It advances no
record sequence. Capture, reads and the availability stimulus are implemented
by the [read evaluator](read-evaluation.md). Declassification, revocation, delivery,
erase and restore are implemented in the same pure state model.

## Conformance measurement

Run `go -C go run ./cmd/memory conformance` from the repository root. The command
reports every whole-vector verdict, exact operation agreement by type and all
six postcondition inventories. Whole-vector comparison remains unchanged and
reports 77/77, including the K-SRC-1 source presentation cases.

| Admission result | Matched | Corpus total |
| --- | ---: | ---: |
| `admit` | 48 | 48 |
| `admit_raw` | 3 | 3 |
| `revise` | 28 | 28 |
| All admission operations | 79 | 79 |
| `load` stimulus | 1 | 1 |

There are no prerequisite exclusions: P11:13/P11:14 exercise retain revocation,
and S26:1 exercises generation rejection after erase. All 79 are required by the
operation ratchet. Declassification is measured separately (2/2).

`conformance.CompareParts` compares exact typed operation results and inventories.
Only valid declared fresh-handle slots within the part are normalized. Handle
relations are checked among available valid endpoints; a missing endpoint outside
the part is judged in its own part and by the unchanged whole-vector comparator.
Thus an out-of-scope final result does not erase independent receipt evidence.
One run establishes handle format and relations, not a statistical distribution.

Both `go/conformance/passing.txt` (whole-vector ids) and
`go/conformance/passing-ops.txt` (admission `vector-id:zero-based-index`) reject
unknown, duplicate and regressed requirements. Newly passing entries are printed.
Tests additionally require every matching admission result and newly passing
whole vector to be persisted.

Current inventory matches, measured over all 77 complete vector executions:

| Inventory | Matched |
| --- | ---: |
| `record_refs` | 77/77 |
| `erased_refs` | 77/77 |
| `custody_present` | 77/77 |
| `dirty` | 77/77 |
| `control_observations` | 77/77 |
| `external_effects` | 77/77 |

These are complete semantic execution results. Custody dispositions model the
closed fixtures; physical deletion and restore isolation need a protected adapter.

## Specification interpretation

K-REC-1 requires an excerpt's exact `retention_admission` reference but the closed
snapshot has no separate retention-admission registry. In S30,
`/initial_state/records/1/body/retention_admission` names `{id: "retention:grounds", version: 1}`,
which is not a record. The kernel treats this as opaque external trusted intake
evidence, requiring its presence and independently checking current retain
rights; it does not require a memory-record lookup for that adapter reference.
This follows the fixture's admitted-complete-snapshot contract (K-API-2).
Authenticity of that external binding remains an adapter/deployment obligation.

K-ENV-1 says a team perspective needs an admitted issuer grant. The closed grant
shape has no team selector; S10's `/initial_state/records/5/envelope/perspective`
and `/initial_state/records/6/envelope/perspective` share a team principal while
the grants name each issuer and space. Admission requires an explicit issuer
`admit` grant in that space and retains distinct issuer sequence keys. It does
not infer a team-membership registry from the spelling of the team principal.
