# Git spaces and verified sync

`space.Repository` is the stage-2 library adapter. It uses explicit `os/exec`
argument vectors, the existing signing/policy layer, the production kernel and
`scan.Scan`. There is no shell, daemon or directory discovery. The [foundation CLI](cli.md) supplies local configuration and the provisional trusted profile.
The remote and branch are explicit caller configuration. Tests use temporary
local bare repositories, isolated git configuration and ephemeral record keys.

## API and trusted inputs

```go
repo, err := space.Open(space.Config{
    Git: space.Git{Directory: clonePath, Environment: gitEnvironment},
    Branch: "main",
    CacheDirectory: privateIndexPath, // outside the clone
    GenesisDigest: trustedGenesisDigest,
    Template: trustedEmptyKernelSnapshot,
    Schemas: schemas,
    Mint: freshUniform128BitHex,
})
// Handle every error before continuing.
err = repo.Sync(ctx)
result, err := repo.Write(ctx, space.WriteRequest{
    Build: buildKernelOperation,
    Signer: identityKey, // sign.WriteSigner; localkey implements it
    MaxRetries: 2,      // at most three push attempts
})
view, err := repo.Read(completeKernelQuery)
```

`space.Clone(ctx, git, remote, branch)` creates a clone with the same explicit
execution environment. Initial `space.json` creation and distribution of its
pinned genesis digest belong to the caller. A space contains signed `space.json`
and immutable `records/<kind>/<encoded-id>/<version>.json` files. IDs are encoded
as lowercase hexadecimal UTF-8 bytes: identifiers remain opaque, path separators,
dot components and case-insensitive filesystem aliases cannot change identity.
Versions use canonical positive decimal. `directory/` is reserved for platform
spaces; its format and interpretation remain out of scope.

The template has an empty records array and complete independently trusted kernel
configuration: domain registry, grants, lineage facts, intake reviews, subject
bindings, representations, projection/evidence policy, initial runtime and bounds.
As with `NewSnapshot`, signed records do not manufacture these authorities. Supply
configuration covering the intended writes; an unknown intake review or lineage
fact refuses rather than becoming automatically trusted. The adapter does not
implement an owner registry or a new protected-service intake profile. `Build`
receives a detached verified snapshot, returns a closed kernel `admit` or `revise`
operation, and runs once per call. The kernel remains the admission authority.

Applications can supply independently trusted `Config.Profile` code to derive
configuration from each verified in-force policy and candidate operation. It runs
after policy transitions and on isolated write/replay candidates. The CLI uses
this seam to re-derive grants and conservative documentary intake; record fields
never establish complete lineage or external authority. See [the profile contract](cli.md#provisional-trusted-profile).

`VerifiedPolicy` exposes the immutable current policy. `InitializePolicy`,
`EndorsePolicy` and `UpdatePolicy` support signed owner administration, verify
the previous owner authority and use ordinary signed commits and pushes. Failed
signing restores only the command-owned policy path; a push race refuses.

Git receives exactly the explicitly supplied, non-nil `Git.Environment`. Callers must provide the intended author,
committer, transport and signing configuration. The library discovers no host
keys, agents, credentials or global configuration. Production commits use `-S`,
are verified before publication and are pushed without force. The explicit
`UnsignedCommits` opt-in exists for isolated tests only. One repository value owns
one working clone/cache pair; separate values/processes must not share that pair.
The working clone must be clean; unrelated tracked, staged and untracked work is
preserved and the write refuses with `dirty_clone`. Writes leave HEAD detached;
existing local branch refs remain intact, including unpublished failed attempts.

## Authenticated admission metadata

Architecture §7.1 needs expected-version, idempotency and intake context in
addition to the closed record envelope. These fields are not present in stored
records. The adapter preserves that record wire format and stores an additional
signed transaction in the commit message:

```text
swarma-memory transactions/1

[{"write":{"origin":{"space":"<space ID>","parent":"<first-parent object ID>","tree":"<complete tree object ID>","policy":"sha256:<policy digest>"},"operation":<kernel operation>,"records":[<signed record>,...],"receipt_handle":"<handle>"},"signature":<signature>}]
```

The transaction payload is closed, canonical and signed under the fourth purpose
`swarma-memory-write/1`, with the same purpose/NUL/canonical-JSON framing. The
immutable `sign.CanonicalWrite` exposes the complete validated request to
`SignWrite`; localkey refuses a different actor or the zero value. It binds the
original operation, the exact signed output records, the original fresh receipt
handle and a closed originating context. That context pins the space, the parent
being extended, the complete proposed Git tree and the in-force policy digest
(which includes its version). Parent/tree use the repository's SHA-1 or SHA-256
object format. The tree is computed without changing the index or working files,
then checked against Git's actual staged tree before committing. It cannot replay
as a record, policy or registration, including retagging.
Commit signatures provide transport history; this separate actor signature binds
admission metadata even when git hosting permits arbitrary commits.

A commit may carry several independent signed transactions. Each kernel transaction
is atomic: failure admits none of its records and reserves none of its output
paths. Bindings become visible only after successful admission and exact output
validation. A bad independent transaction or extra forged file does not suppress
a valid neighbour. Unbound files receive
`missing_transaction`; valid signatures alone do not establish admission. No
unsigned commit-message field grants identity, representation or an intake fact.

## Replay and policy forks

Sync fetches the configured branch and walks its **first-parent history**, oldest
first. At each position:

1. A changed policy is parsed and appended only if it extends the accepted,
   genesis-anchored chain. An invalid policy is diagnosed and the previous verified
   policy remains in force. A competing owner-signed version cannot replace the
   first accepted version. A continuation of the losing fork also fails
   `policy_sequence`. A continuation of the winning branch can still succeed.
2. New record files verify purpose, registered submitter key, signature, closed
   schema/domain, space, complete writer grant, limits and non-sensitive ceiling
   against that exact in-force policy.
3. Signed transactions replay through `State.Write`, including issuer/representative
   revision authority, expected version, idempotency, references, retention,
   lineage and every other kernel admission constraint. Rejected records stay out
   of the evaluation snapshot and appear in `Diagnostics()`.

Policy changes precede records introduced by the same commit. Removing a writer
or rotating its key does not retrospectively revalidate earlier records under the
latest registry. An invalid policy update cannot grant its accompanying record.
Only the changed policy visible in each first-parent tree is considered; skipped
intermediate versions on a side branch do not establish in-force transitions.

A merge introduces side-branch files at the merge's first-parent position.
Transaction metadata is recovered from the messages of **newly reachable** commits,
then applied only to files newly introduced at that position. The signed parent
and tree must match the actual source commit, whose tree must itself introduce
the exact signed outputs. A metadata-only carrier cannot authorize files added
elsewhere. The policy digest must match the accepted policy at replay, including
policy-first updates in the same commit. A context mismatch is diagnosed as
`transaction_origin_mismatch` or `transaction_policy_mismatch`.

A legitimate secondary-parent merge retains each source commit's authenticated
parent/tree; it does not rebind signatures to the merge tree. Copying a transaction
into a different parent or tree, or under another policy, requires a new signature.
In particular, adding an independent neighbour at the same parent changes the
tree and cannot reuse a source signature. Commits with the same parent, complete
tree and policy represent the same authenticated write intent; author, timestamp
and unrelated message text are not actor-authenticated context. No self-referential
commit ID is required. An explicit write retry re-admits and signs the new context.
Fetch order and
secondary-parent timestamps have no authority. Independent transactions at one
position are ordered by the first record path, then canonical transaction bytes.
Competing sequences yield `version_conflict`; independent sequences can both admit.

A signed file is never restamped. Concurrent writers can have identical local
`recorded.sequence` annotations. The kernel evaluation index derives that sequence
from its first-parent admission cut instead; this is a detached projection after
signature verification. Every other admitted field must exactly match the signed
record, including timestamp, submitter, lineage, disclosure, body and checked
representation. Mismatches yield `admission_output_mismatch`. This keeps ordering
in history and preserves the original signature bytes on disk.

Any change to a previously encountered record path, including deletion, mode
change or repair of an invalid file, yields `record_rewritten`; it never changes
previously admitted evidence. A new legitimate version needs a new path. The first
accepted transaction extending a sequence wins, regardless of fetch order.

## Writes, races and scans

The write path synchronizes, builds once, admits into an isolated kernel fork,
checks policy, scans before requesting any signatures, signs records and their
transaction, commits on the verified remote parent and pushes. The scanner checks
the admitted records plus persisted context/idempotency metadata. Record/field
byte caps come from policy. Since policy has no separate array-length limit, the
scanner's array cap equals its record byte cap (an array that large already exceeds
that canonical-byte bound). Findings remain typed and fully redacted.

On a rejected push, fetch and check the unchanged operation against the new verified
head. A changed expected version returns `version_conflict` immediately. An
idempotent write already published returns its original receipt. Other admissible
races rebase the local intent onto the new parent by repeating admission, scanning
and signing; the newly stamped output needs new signatures. No force push or git
conflict-resolution merge is used. `MaxRetries` bounds additional attempts;
exhaustion returns `retry_exhausted` and leaves the latest verified remote state
available. Transport failures without an advancing remote remain `git_failed`.
An unpublished attempt remains reachable in the clone's reflog for inspection.

## Cursors, reads and rebuild

One `index.json` outside the repository atomically stores cursor, admitted snapshot
and diagnostics. The cursor identifies the last processed commit, including
positions with rejected inputs. At open, only the pinned cursor is read from the
index; its state is reconstructed from local git objects with the current trusted
configuration. Cached snapshot bytes never inject records or authorities. Replay
receipts are authenticated transaction data, so rebuilding a fixed history with
the same trusted configuration produces byte-identical canonical snapshots and
diagnostics. Read responses still mint fresh opaque handles as required by the
kernel; those fresh handles are not stable rebuild identifiers. The rebuild gate
compares the full canonical evaluation view after replacing only that fresh handle,
checking equality at every declared handle position. All other view bytes and the
entire canonical storage snapshot/diagnostics must match exactly.

If a fetched head omits the verified cursor from its first-parent line, sync
returns `history_rewritten` without changing the cursor, snapshot, diagnostics or
index file. This also rejects re-adding identical files under different commits,
and rejects moving the old cursor to a secondary parent. Reads continue from the
last verified state, including after reopen, while its git objects remain locally
available. Losing those objects is an explicit reconstruction error, never an
excuse to silently reset the cursor. Deleting the index intentionally resets this
rollback protection and rebuilds from the currently fetched history.

`Read` delegates complete recall/explain/changes queries to the kernel after the
latest verified policy authorizes `principal` or `public`. `Reader.Spaces` is
reserved metadata for future space-identity/directory integration; it confers no
additional principal access. Kernel disclosure/retention grants still apply.
`ChangesSince(ctx, query, commit)` reconstructs a protected kernel capture at a
verified ancestor, then replays to the current cursor. Unknown cursors and changed
query bindings refuse. `Capture` offers an in-memory baseline until the next sync.

`ReadSpaces(ctx, []SpaceQuery)` syncs and reads every explicitly requested space,
returning a collection sorted by space ID. Each entry carries its cursor,
diagnostics and complete kernel view, including sources, perspective, bounds and
`data` classification. The kernel query schema pins one space and one issuer
projection, so this API preserves those independent views rather than inventing a
cross-space cut or revision order. Request another configured projection to read
another issuer. On history rewrite it returns the last verified views together
with the rewrite error. Other errors return no partial collection.

## Architecture decisions and limits

| Section | Ambiguity | Decision |
| --- | --- | --- |
| §5.2 | Opaque IDs may contain path separators or case aliases | Lowercase hexadecimal path component; exact `RecordPath` match required. |
| §5.3 / §6.3 | Two genesis-valid owner forks and same-commit policy/record changes | First-parent accepted chain; policy first in a commit; rejected forks never grant authority. |
| §6.3 / §7.1 | Record wire omits the original admission operation and receipt | Additional purpose-separated signed transaction in commit metadata; unsigned/unbound records are diagnosed. |
| §6.3 / §7.3 | Signed metadata could be transplanted to another commit or policy | Bind space, parent, complete source tree and in-force policy digest; verify source outputs and preserve source context through merges. Identical parent/tree/policy means identical authenticated intent. |
| §6.3 / §7.3 | A side commit's signed local sequence can collide with the first parent's | Preserve signed file; project only sequence into the evaluation index using kernel replay position. |
| §6.3 | Source of kernel intake/registry facts | Explicit independently trusted empty template, as at `NewSnapshot`; never derive authority from a proposed record. |
| §7.1 | Rebase after admission changes recorded position | Re-admit, scan, sign and commit on the fetched parent; no force push. |
| §7.1 | Meaning of retry bound and lost push acknowledgement | Additional attempts; recognize an already committed idempotent receipt before exhausting. |
| §7.1 / §5.3 | Scanner has an array cap absent from signed policy | Use record byte cap as a conservative array bound. |
| §7.3 | Multiple transactions enter through one merge/commit | Path/canonical-byte tie-break at that first-parent position; atomicity stays per kernel operation. |
| §8 | Kernel reads pin a single space/issuer projection | Return sorted complete per-space views; caller explicitly selects each issuer projection. |
| §9 | Cursor remains an ancestor only via a secondary parent | Refuse as rewritten history: the accepted first-parent line must survive. |
| §8 / §9 | Rebuild equality versus mandatory fresh response handles | Compare canonical storage exactly and complete views with only equality-checked fresh handles normalized, as in conformance. |
| §9 | Cache lifetime and deterministic rebuild | One external atomic index file; reconstruct from cursor objects, fixed trusted configuration and authenticated receipt handles. |

This is a library, not a hosted service or hostile-filesystem sandbox. The caller
owns clone/cache isolation, configuration authenticity, genesis distribution,
record-key custody, git transport access and retention of verified git objects.
Owner retirement actions, directory contents, CLI, installation, promotion,
escalation and protected-deployment qualification remain separate stages.

## Validation

Run from the module root:

```sh
go vet ./...
go test ./...
go test -race ./space
go run ./cmd/memory conformance
python3 -B spec/checks/validate.py
```

`space/git_test.go` contains claim-commented real-git gates for concurrent writers,
NFF retries and bounds, stale expected versions, merged competing and independent
sequences, both policy-fork orders and an actual policy merge, all five required
forgery classes with valid same-commit neighbours, transaction tampering, rewrite
with identical re-added files, reopen/rebuild, cross-identity reads and revisions,
two-space recall, explain/changes, scan-before-sign and dirty-state preservation.
All test git environments discard inherited `GIT_*` and `SSH_AUTH_SOCK`, disable
system/global config and commit signing, and set explicit synthetic authors.
A control test plants forbidden overrides and fails if they leak. Remote rewrites
use an atomic `update-ref` inside the temporary bare fixture to model the exact
force-push reference transition without issuing a force-push command. Optional
logs belong in ignored `.temp/`.

`space/git_rework_test.go` additionally preserves source-commit and policy
transplant witnesses, isolates all authenticated context fields, checks SHA-1 and
SHA-256 trees against Git, and pairs overlapping stale-generation/output-mismatch
refusals with valid transactions and a valid-only control. CI retains the space
race gate alongside the normal tests.
