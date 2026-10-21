# Git spaces and verified sync

`space.Repository` is the stage-2 library adapter. It uses explicit `os/exec`
argument vectors, the existing signing/policy layer, the production kernel and
`scan.Scan`. There is no shell or daemon; platform directories supply discovery metadata. The [foundation CLI](cli.md) supplies local configuration and the provisional trusted profile.
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
spaces; its signed format is described in [Platform directory](#platform-directory).

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

Sync aligns a clean checkout with its verified cursor using an ordinary detached
switch; it preserves pre-existing dirty caller work. Write requires a clean
clone and also restores that verified checkout on refusal, including a losing
NFF attempt; the signed unpublished commit remains in reflog. Cleanup uses a
bounded independent context so cancellation does not leave a refused commit
checked out.

An optional `WriteRequest.Precondition(snapshot, cursor)` applies application
freshness constraints after kernel admission, before publication and after every
NFF fetch. It receives detached verified data and grants no authority. The CLI
uses it for explicit read-bound target tokens, including assessment/challenge
operations whose kernel semantics allow historical targets. These preconditions
do not change the signed kernel operation or its replay semantics.

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
Owner retirement actions, escalation and protected-deployment qualification
remain separate stages; the CLI implements directory discovery and local promotion.

## Validation

Run these commands from the repository root:

```sh
go -C go vet ./...
go -C go test ./...
go -C go test -race ./space
go -C go run ./cmd/memory conformance
python3 -B spec/checks/validate.py
```

`go/space/git_test.go` contains claim-commented real-git gates for concurrent writers,
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

`go/space/git_rework_test.go` additionally preserves source-commit and policy
transplant witnesses, isolates all authenticated context fields, checks SHA-1 and
SHA-256 trees against Git, and pairs overlapping stale-generation/output-mismatch
refusals with valid transactions and a valid-only control. CI retains the space
race gate alongside the normal tests.

## Platform directory

A platform repository additionally contains
`directory/<lowercase hex UTF-8 space_id>/<positive decimal version>.json`.
Each file is a closed `{entry, signature}` publication. Its entry contains:

```text
format: swarma-memory-directory/1
 directory_space, space_id, version, previous, status, advertisement, author
```

`previous` is null at version 1, otherwise the previous accepted entry's framed
payload digest. Status is `active` with a signed advertisement, or `withdrawn`
with null. The advertisement wrapper is `{advertisement, signature}`; its payload
has `format: swarma-memory-space-advertisement/1`, `space_id`, `kind`, `bindings`,
`git: {remote, branch}`, `genesis_digest`, `observed_policy: {version, digest}`,
and `author`. Bindings are sorted unique `{kind: identity|project, id}` lookup
keys, never readers/access hints. No expiry is supported.

`Repository.Advertisement` creates a typed owner-signed advertisement from verified
state. The local caller supplies the configured transport and explicit bindings.
`PublishDirectory` signs with a current platform owner, commits with `-S`, verifies
that commit and ordinarily pushes. It serializes version allocation after sync;
a racing publication refuses `version_conflict` without force-pushing.

Replay applies policies before entries at each first-parent position. It checks
closed schemas and purposes, the platform ID and exact path, historical publisher
ownership/key/signature and version/previous continuity. `directory_sequence`
keeps the first accepted version. Changed/deleted accepted files produce
`directory_rewritten` and cannot replace the accepted head; a competing signed
version at that same immutable path also produces `directory_sequence`.
`directory/` outside a platform space produces `directory_not_platform`.
Within a single commit, versions for one encoded space ID are checked in numeric
order, before invalid path spellings. Invalid neighbours are diagnosed independently and never affect the kernel view.

`Directory` returns sorted detached heads and status, under current platform
reader authorization. `LookupDirectory` refuses withdrawn/stale heads. A stale
publisher is one no longer present in current platform owners. On use,
`VerifyAdvertisement` requires the target's genesis-anchored chain to reach the
exact observed policy version/digest, verifies the owner/key at that version,
and matches ID/kind. Invalid targets give `directory_mismatch`; no config or
permanent clone/cache is saved. The directory supplies pins, never grants.

CLI discovery uses a private staging clone/cache, then installs them and publishes
config only after all validation succeeds. Existing different genesis pins refuse
`genesis_conflict`. Update relocates under the same pin and requires the existing
verified cursor on the new remote's first-parent line (`history_rewritten`).
Dirty existing clones refuse replacement. A failed update preserves config,
clone and cache. Existing configured spaces keep their own pins after withdrawal
or publisher removal, with `directory_diagnostic` on `sync`/`check`; neither event
revokes target grants or Git access.

Advertised remotes permit HTTPS and SSH (URL or SCP form) only; file URLs/absolute paths require
explicit `GIT_ALLOW_PROTOCOL` containing `file` for isolated tests. Helpers
(including `ext::`), option-shaped URLs and control characters refuse
`directory_transport` before target Git starts. Clone passes its URL after `--`
and uses `DirectoryEnvironment` to constrain `GIT_ALLOW_PROTOCOL` to SSH/HTTPS
(and explicitly opted-in file) during clone and subsequent target sync. This
blocks helpers selected through `insteadOf` even when per-protocol configuration
explicitly enables them. Other environment/authentication remain caller-owned.

Use `<owner>/<id>` for cross-owner identities and space names. The namespace
anchor is the genesis owners' prefix, **not** a space-name prefix. All owners must
share it; registration and grant identities must be qualified in qualified spaces.
Foreign registrations and named reader grants are accepted: the local owner's
registration signature attests identity, while raw public-key bytes disclose no
origin. Foreign writer grants refuse `cross_owner_writer`; unqualified identities
in qualified spaces refuse `identity_owner_mismatch`. Wholly unqualified,
single-owner legacy spaces remain supported without mixing qualified identities.
Promotion across namespace anchors refuses `cross_owner_promotion` in v1.

The two-owner stage-5 integration gate, delegated publishers, key-bearing identity
entries, expiry, federation and a shared cross-owner directory remain outside this
adapter feature.

## Resolver policy v2 and read-only escalation

Current owner-created policy payloads use `format: "swarma-memory-policy/2"`
([payload schema](../go/space/schema/policy-v2.schema.json)). The signature's
framing purpose stays `swarma-memory-policy/1`; the signed discriminator selects
the new payload schema. Legacy payloads omit `format` and their signature bytes
are never rewritten. Only a new owner-signed transition upgrades them.

Each `resolvers` entry is closed `{area,match:{schemas,subjects},identities}`.
Area labels are unique and carry no classification semantics. Match lists and
identity lists are sorted/unique; schema refs must be accepted by the policy.
A route matches exact schema AND exact subject, with an empty list meaning any.
One both-empty catch-all is allowed. Non-catch-all overlaps, and a second
catch-all, refuse signing and verification with `resolver_overlap`. Listed
identities need registered keys and explicit reader/writer grants in the same
policy and qualified namespace (`resolver_unqualified` otherwise). Failed edits
leave the prior verified policy in force; routing grants no extra authority.
Owner-only `policy resolvers set|remove|show` administer these entries.

Legacy entries with no match are read as one catch-all union of identities;
area prose is ignored. `spaces show` returns `resolver_warnings` for legacy
unqualified recipients. A new transition upgrades that union to one `legacy`
catch-all and must fix any unqualified recipients before it can be signed.
No match routes to the space's owners with basis `default_owners`.

`conflicts`, and `explain`/`recall --require-current`, use the current verified
policy at each item's own Git cursor. Packets contain only authorized refs and
metadata, no content/excerpts/prose. Hidden and missing reported refs both refuse
without a partial packet. Cross-space reported contradictions keep distinct
(space, route) blocks with a shared key over the full ref set; detected conflicts
have independent keys over their own exact refs. Memory only performs normal Git
sync and returns data; it has no board client, notification or other network
path. See [CLI routing and resume rules](cli.md#exact-conflict-checks-and-resolver-policy).
