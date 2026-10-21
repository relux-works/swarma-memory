# Memory CLI: administration, reads and writes

Build `go -C go build -o ../bin/memory ./cmd/memory`. The application embeds the public
package schemas, domain documents, semantic vectors and conformance ratchets,
and runs outside the source checkout. Default `conformance` is independent of
working directory; an explicit vectors path is resolved from the caller's cwd.

## Home and config

`--home DIR` (any argument position) overrides `MEMORY_HOME`. Either selects one
directory for config, keys, clones and caches. Otherwise config and the temporary
identity key live under `$XDG_CONFIG_HOME/swarma-memory` (default
`$HOME/.config/swarma-memory`), and clones/caches under
`$XDG_STATE_HOME/swarma-memory` (default `$HOME/.local/state/swarma-memory`).
The home must be outside Git working/bare repositories and metadata directories, including symlink aliases.

`config.json` has exactly `identity`, `key_file`, and `spaces`; its closed
[schema](../go/cmd/memory/config.schema.json) is enforced on load. Each space has
exactly `id`, `remote`, `branch`, `clone_path`, `cache_path`, `genesis_digest` and
`kind` (`agent`, `project`, `platform`), plus optional `directory_space` recording
the platform used for discovery diagnostics. Clone/cache names are SHA-256 encodings
of IDs under `clones/` and `caches/`; paths must match those locations and cannot
redirect through symlinks. The explicit key path must match `localkey.json` in
the config home. There is no local authority or grants field; additional fields
refuse with `invalid_configuration`.

The home/config directories use 0700; config and key files use 0600. Config writes
use a private temporary file, fsync and rename. Existing config/key files are
never overwritten by `keys init`. Generated/saved keys must fit the loader's
4096-byte encoded JSON bound, including identity escaping and UTF-8; unsupported
identities refuse `invalid_key` before publishing key/config state. Config has a
shared save/load bound of 1 MiB including its trailing newline, and the same
closed-schema/path checks apply in both directions. Initialization and space
add/init preflight the complete prospective config before creating a key/clone
or publishing genesis; refused inputs preserve existing config and permit a
valid retry. Invalid UTF-8 refuses instead of being silently replaced during
encoding. A process owns its home exclusively; concurrent
processes must use separate homes, just as independent library instances must use
separate clones and caches. Remote publication still uses non-fast-forward gates.

## Commands

Every command accepts `--json`; examples omit it for brevity. `--` terminates
flag parsing for literal queries/IDs beginning with dashes. IDs are opaque;
`explain` uses a separate `--version` flag and never splits an ID at punctuation.

| Command | Arguments and behavior |
| --- | --- |
| `keys init --identity ID` | Create one temporary local Ed25519 key and config |
| `keys show` | Public identity, key ID, algorithm and base64 public key; no private material |
| `spaces list` | Sorted configured spaces |
| `spaces add ID --remote URL --genesis DIGEST [--branch main] [--kind project]` | Clone, verify the externally obtained genesis pin, then save configuration |
| `spaces init ID --remote URL [--branch main] [--kind project]` | Clone an empty remote, sign owner registrations and genesis policy, commit with `-S`, verify and push; return the genesis digest for distribution |
| `spaces add ID --from-directory PLATFORM` | Discover through the pinned own-owner platform; verify target in staging, then save its pin |
| `spaces update ID --from-directory PLATFORM` | Relocate an existing space under its unchanged genesis and first-parent cursor |
| `directory advertise --space ID --out FILE [--bindings FILE]` | Target owner exports a signed advertisement from the verified clone; output must not already exist |
| `directory publish --space PLATFORM --entry FILE` | Platform owner wraps, signs, commits and pushes the supplied signed advertisement |
| `directory withdraw --space PLATFORM --space-id ID` | Publish the next version as a withdrawal |
| `directory list --space PLATFORM` | Sorted current heads with active/withdrawn/stale state and replay diagnostics |
| `directory show --space PLATFORM [--space-id ID]` | All heads, or one selected head, with replay diagnostics, as data |
| `spaces show ID` | Sync and return verified policy, digest, cursor and diagnostics |
| `keys register --space ID --identity ID --public-key BASE64` | Current owner endorses a key in a new signed policy version |
| `policy grant --space ID --identity ID --role reader\|writer` | Current owner replaces that identity's role grant in a new version |
| `policy revoke --space ID --identity ID --role reader\|writer` | Current owner removes that role grant in a new version |
| `policy resolvers set\|remove\|show --space ID ...` | Owner-only exact resolver routes; see below |
| `conflicts --space S --id ID [--task T --step STEP]` | Read-only exact-dependency packet, exit 0 or 7 |
| `conflicts --ref SPACE:ID:VERSION ...` | Caller-reported packet, exit 7; hidden/missing ref exits 3 |
| `sync [--space ID]` | Fetch/verify configured spaces and advance verified cursors |
| `check [--space ID]` | Same verification, with exit 5 if any diagnostics exist |
| `recall QUERY [--rule issuer_current] [--require-current]` | Case-insensitive substring search over authorized structured assertion content; `*` selects every authorized assertion |
| `explain ID [--version N] [--require-current]` | Kernel explanation for authorized assertion versions, including historical versions when explicitly selected |
| `changes [--since CURSOR]` | Kernel view changes from a protected replay baseline; omitted baseline means initial view |
| `add KIND --idempotency-key KEY ...` | Atomically admit an assertion, source, justification or assessment |
| `revise ID --relation replace\|withdraw\|correct\|challenge --idempotency-key KEY ...` | Kernel revision with a pinned compare-and-set token |
| `assess ID --kind CHECK --idempotency-key KEY ...` | Admit a pinned assessment |
| `promote ID --space SOURCE --to TARGET --idempotency-key KEY` | Read an authorized assertion and admit a separately attributed derivative with a citation in a configured target |
| `version` | Build version |
| `conformance [VECTORS-DIR]` | Existing semantic harness and inventories |

Relative filesystem remotes resolve from the caller's working directory; transport
URLs and SCP-style remotes pass through unchanged.

Reads also accept `--space ID` and `--at YYYY-MM-DDTHH:MM:SSZ`. The latter pins
logical evaluation time for reproducible queries; otherwise the process clock in
UTC is used. Recall selects validity at that instant; explain/changes use `any`
validity to retain historical evidence. Default reads sync every configured
space, omit unreadable spaces, and refuse `not_authorized` if none is readable.
Named reader identities require possession of a local key registered for that
identity in the **current verified policy**. Editing `identity` in config cannot
impersonate a registered reader. A signed `public` reader grant in a legacy unqualified policy uses the public
audience and needs no named registration. Named readers use the private audience.

Genesis explicitly grants the owner both reader and writer roles. An owner title
alone gives no implicit read/write role. Reader grants derive `read/use`; writer
grants derive `admit/retain/revise` only. Owner commands require the preceding
policy's registered owner key. Each new version re-endorses retained key entries
at that version. A writer grant covers the policy's accepted schemas, all five
record kinds, and machine observation, self declaration and semantic inference
classes; the signed policy still checks each record's exact class/schema/kind.
Reader `spaces` metadata grants no additional authority.

Read output has a composite `memory:1:<base64url canonical space/cursor map>`
cursor. Pass it unchanged to `changes --since` across spaces. A raw Git commit
cursor is accepted when selecting exactly one configured space. Every readable
space must have a baseline entry, and each commit must be a first-parent ancestor.
Unknown/future/rewritten baselines refuse `invalid_cursor`, including empty spaces.
Views remain separate per space and exact subject/schema/issuer/perspective; the
CLI asserts no cross-space authority or global order. Changes compare authorized
kernel views, not arbitrary Git file edits. Current reader authorization is
required even when reconstructing an older baseline. Baseline evaluation uses its
own policy, then current evaluation uses the latest verified policy.

Every kernel view carries `sources`: exactly the deduplicated entries cited by
its displayed items, ordered by id and numeric version. Live entries include
locator fields, effective availability and `{state: "present", text}` or
`{state: "none"}`. An unavailable session keeps its retained excerpt. Erased
entries contain attribution and `{state: "erased"}`, with no locator, digest,
origin or text. Hidden sources produce no entry or placeholder. Audience
projections carry `sources: []`. This presentation creates no witness and cannot
satisfy a current source requirement. `changes` includes an item when a cited
source entry changes; captures freeze the table with the items.

`--json` passes these kernel entries through byte-exactly, including multiline
Unicode text. Recall's text filter retains only entries still cited by displayed
items. Compact output includes the data envelope plus decoded locator,
availability and retained excerpt lines. Sources are never separately enumerable.

## Write commands

Writes use the same home, local signer, trusted profile and verified policy as
reads. They call `space.Repository.Write`: sync, build once, kernel admission,
scan, record/transaction signatures, `git commit -S`, signature verification and
ordinary push. The fixed bound is **two additional push attempts** (three total).
Each rejected push fetches and rechecks the unchanged operation. A changed CAS
head yields `version_conflict`; an unrelated admissible race can retry. No force
push or merge is used. An unpublished signed racing attempt remains in the local
reflog; the remote receives only accepted writes and the clone remains clean.

All four commands require `--idempotency-key KEY`. `--space ID` selects a configured
space; it can be omitted only when exactly one is configured. Promotion requires
an explicit source selection when more than one space is configured. `--id ID`
names the new primary record, default `record:KEY`. Do not use secrets as keys or
IDs: these metadata are scanned too. The same actor/space/key and complete intent
returns the original kernel receipt, including its handle, under current grants
and retention. Changing the body under the key gives `idempotency_conflict`.
A retry never bypasses the kernel by returning a locally cached receipt.

Common write flags:

| Flags | Meaning |
| --- | --- |
| `--body FILE` or `--body -` | Complete closed JSON body, read from a file or stdin; never an envelope/operation override |
| `--content TEXT` | Assertion shorthand: one `value` field, `slot: "[]"`, no authority receipt; mutually exclusive with `--body` |
| `--at UTC` | Intake timestamp in UTC seconds; default process clock |
| `--expected-generation N` | Explicit erasure generation; default verified current generation, or original generation on exact retry |
| `--id`, `--idempotency-key`, `--space` | Record identity, retry identity and target space as above |

Inputs are UTF-8, at most 1,000,000 bytes per file/stdin input, with strict JSON
parsing for body/source files. Exactly one input can consume stdin. Invalid body
shape, unknown fields, domain content, grants, representation and bounds still
pass through the existing closed-schema/kernel checks. Plain output retains the
same quoted `memory data:` envelope as JSON mode.

### Add

```sh
memory add assertion --space project:example --id record:observation \
  --idempotency-key observation:one --content 'An attributed observation'
memory add assertion --space project:example --idempotency-key observation:two \
  --schema schema:assumption --schema-version 1 --body body.json
```

`KIND` is `assertion`, `source`, `justification` or `assessment`; revisions use
`revise`. Non-assertion kinds require `--body`. Assertions default to
`schema:assumption` version 1 and statement kind `fact`. `--statement-kind` changes
the shorthand's kind; it cannot accompany a full body. Other domains, sorted
content fields and slots are supplied by full body JSON.

Envelope flags are `--subject`, `--issuer`, `--perspective own|observer|team`,
`--perspective-principal`, `--schema`, `--schema-version`, `--version`,
`--valid-from`, `--valid-to`, and `--confirmed-at`. Defaults are local identity for
subject/issuer, own perspective naming the issuer, version 1, validity beginning
at the initial intake time with no end, and no claimed confirmation time.
Schema flags apply only to assertions. The omitted initial validity start is
recovered from the verified original operation on retry. `--admission-class`
defaults to `machine_observation`; choose `semantic_inference` with a matching
proposal/assessment-summary schema for model-created statements. Explicit issuer
or team flags grant no authority. Kernel intake supplies submitter, recorded
stamp and class; the provisional profile keeps lineage unknown.

`--sources FILE|-` accepts an array of exact source refs, such as
`[{"id":"source:notes","version":1}]`. An assertion and a documentary-basis
justification are admitted atomically. An assessment appends these refs to its
`sources`. This establishes documentary attribution, without a world-evidence
root, independent origin, sufficient-support proof or fresh source resolution.
The kernel rejects missing or non-source refs with `invalid_reference`.

### Revise and assess

```sh
memory revise record:observation --space project:example --relation replace \
  --content 'Updated observation' --expected-version 1 --idempotency-key update:one
memory assess record:observation --space project:example --kind semantic_review \
  --executor model --result pass --expected-version 2 --idempotency-key review:one
```

`revise` supports all four architecture relations. `replace`/`correct` require
`--content` or the complete replacement `--body`; the replacement preserves its
sequence envelope, receives the same ID and next version, and is atomic with the
revision. `withdraw`/`challenge` accept neither content nor body. The revision
itself uses `--id` (or `record:KEY`), version 1, and the target's subject. Its issuer
defaults to the local identity (`--issuer` and `--admission-class` are explicit
inputs, subject to kernel authority).

Every `revise` relation and `assess` requires an explicit caller-observed
`--expected-version N` or `--expected-token TOKEN`. Missing both gives `usage`,
exit 2, with stderr naming these flags. They are mutually exclusive. A stale
precondition gives `version_conflict`, exit 3; a write never silently substitutes
a newly fetched version for the one the caller observed.

`recall` and `explain` expose `write_token` on each disclosed item in both JSON
and compact output (null when the kernel withholds the item ref). Pass that exact
string with `--expected-token`. It binds the disclosed space, record/version and
verified read cursor. This conservative token becomes stale after **any** space
commit, including an unrelated write: read again or use the numeric record-version
token when unrelated commits should be tolerated. The token is quoted data, not
an authorization capability, signed view or grant. It contains only metadata
already disclosed by the read; it reveals no hidden revision identifiers.

For a numeric token, use the disclosed item's `ref.version` with
`--expected-version`; its ID is the command's record ID. This pins both the target
version and expected token rather than selecting the latest version after sync.
`--expected-id ID` with it can name a withdrawal receipt's revision reference;
the target is then pinned to that withdrawal's original target. `--version N`,
when supplied, must agree with the pinned target. A withdrawn record can be
omitted by the kernel read projection; restoration then requires the explicit
withdrawal receipt token, rather than inventing a read token for hidden data.

Build runs once. An optional adapter freshness precondition is checked against
verified state after kernel admission and after every NFF fetch. This also guards
`challenge` and `assess`, where the kernel intentionally permits historical
references. It changes the CLI's read/write precondition, not the kernel's
admission semantics: authorization, representation and unique sequence-head
admission remain kernel decisions. Original-token idempotent retries keep their
original target and receipt under current authorization, even after later writes;
a retry still must supply an explicit token. Non-issuer replace/correct/withdraw
refuses `representation_invalid`; a separately admitted writer may challenge.

`assess` accepts `--version` for the target and requires `--kind` from the closed
assessment check kinds. Defaults are `--executor model`, `--result pass`,
`--polarity support`, `--source-requirement current`, and `--origin origin:ID`.
Policy/environment pins come from the trusted profile; the check rule is the exact
`check:KIND` version 1. Model checks remain restricted to `semantic_review` by the
kernel. `--body` supplies the complete assessment body instead of these shortcuts;
its check kind and subject pin must match the command and selected record. An
assessment retry retains its explicitly selected target. Envelope issuer and
perspective flags are accepted, while the target fixes subject and output version
is 1. Assessments also accept source/session flags.

### Session excerpts

```sh
memory add assertion --space project:example --idempotency-key session:one \
  --content 'Observed session outcome' \
  --source-session runtime:session:message --source-text excerpt.txt
```

For `add assertion` and `assess`, `--source-session runtime:session:message` requires
`--source-text FILE|-`. The first two colons delimit runtime and session; the rest
is the exact message ID or index. The text is retained byte-for-byte as UTF-8 in
an atomic source record's `body.excerpt`. Its digest is
`{algorithm: "sha256-bytes-v1", value: "<lowercase SHA-256 hex>"}` over the exact
UTF-8 retained text, including trailing newlines, with no framing. **This digest
covers the retained text, not necessarily the whole message.** It is distinct
from the canonical-JSON digest `sha256-cjson-v1`.

New session sources use `owner: runtime:<runtime>`, `object: session:<id>`,
`revision: message:<id>` or `index:<n>`, `provenance: reported`, and
`availability: unavailable`. Explicit `message:`/`index:` prefixes survive;
bare decimal positions use `index:` and other IDs use `message:`. The canonical
JSON `origin` preserves the original runtime/session/message components. A
retention-admission reference names this signed intake but grants nothing;
retain rights are checked independently. A documentary link or assessment source
ref cites it in the same atomic transaction. No live session resolver is claimed.
Legacy sources with the hash in `object`, null `digest` and locator in `origin`
remain valid and render exactly as stored.

### Promote

`promote ID --space SOURCE --to TARGET` accepts `--version N` to pin the original
assertion. It requires a configured distinct target, a registered source reader
(or public grant), per-record disclosure eligibility in a kernel explain query,
and target admission/retain rights. It never uses a raw cached record as a read
capability. A hidden source is not promotable even with a reader role.

The derivative has a new ID, version 1, local issuer/own perspective, the original
subject/schema/content/validity, and the original disclosure labels. The batch
also includes a local source citation naming the original space and exact
id/version, with its `sha256-cjson-v1` digest and original issuer, plus a documentary
justification. No cross-space exact reference, directory lookup, complete lineage,
receipt authority or fresh resolver is invented. The documentary profile still
reports unknown lineage; independently authenticated cross-space lineage remains
an integration question. Target schema/authority checks can still refuse (for
example a foreign self declaration cannot become the new issuer's declaration).
Promotion across owner namespaces refuses `cross_owner_promotion`: v1 has no
forward-right contract. Legacy unqualified spaces compare their single owners.
The latest source version is the default; use `--version` for a stable citation
when retrying after the source has advanced.

### Write results and refusals

Success data has exactly `id`, `version`, `commit`, `cursor`, `receipt`. `receipt`
is the unchanged closed kernel receipt, including all atomic output refs and its
original handle. For replace/correct, id/version name the replacement; for
withdraw/challenge they name the new revision. `commit` is the first-parent commit
that introduced that primary record, even on an idempotent retry. `cursor` is the
current verified target head and can advance independently of the original
receipt. This distinguishes publication identity from current sync position.

| Code | Exit | Result |
| --- | ---: | --- |
| `version_conflict` | 3 | Stale/ambiguous CAS or duplicate output; no accepted write |
| `idempotency_conflict` | 3 | Same key, different complete intent |
| `scan_refused` | 3 | `data: {findings: [...]}` with the scanner's fully redacted typed findings |
| `not_authorized` | 3 | Missing operation/retain grant, or no source reader for promotion |
| `representation_invalid` | 3 | Non-issuer revision or unavailable representation |
| `history_rewritten` | 4 | Preserve last verified cursor; write publishes nothing |
| `retry_exhausted` | 3 | Additional NFF retries exhausted |
| `usage`, `space_required`, `unknown_space` | 2 | Flag/input selection |
| `input_io` | 6 | Input could not be read, without printing its path or content |

Other kernel/sign/adapter refusals retain their typed exit 3 codes. A scanner
quarantine in the provisional intake profile is rendered as `scan_refused` only
when scanning the exact rejected proposals confirms redacted findings; unrelated
quarantine remains `quarantined`. No rejected body or raw Git stderr is emitted.
Pre-publication refusals create no record file or commit and perform no push.

### Architecture decisions

| Section | Ambiguity | Decision |
| --- | --- | --- |
| §7.1 / §11 | Common flags, stable identity/time, original receipt vs current cursor | Required caller key; documented stable IDs/defaults, recover original intake defaults from verified intent, preserve original receipt/commit and report current cursor separately. |
| §7.1 | Retry bound and a losing push's local commit | Two additional attempts; align the clean checkout to the last verified cursor on every Write return, keeping the signed unpublished attempt only in reflog. |
| §7.1 | Provisional scan quarantine precedes the adapter's post-admission scan | Translate only confirmed scanner quarantine to typed redacted findings; no admission rule or profile change. |
| §7.2 / K-SRC-1 | Session source presentation and digest scope | The kernel joins cited source entries; new sources separate runtime owner, session object, message/index revision and raw retained-text digest. Legacy fields render as stored. |
| §7.1 / K-REV-1 / review B1 | Read-to-write races and exact retry after head changes | Require caller-observed numeric/read tokens for revise and assess; pin target before sync can retarget it; recheck freshness after NFF; original-token replay retains its receipt and kernel authority checks. |
| §11 | Assessment defaults and check execution | Pin documentary evidence; never execute the check or turn a model check into deterministic evidence. |
| §11 / stage 5 boundary | Promotion before a directory or cross-space lineage integration exists | Only configured spaces; kernel source read plus target write; preserve disclosure and create a local documentary citation with unknown lineage. |

## Provisional trusted profile

The built-in `agentprofile` is an independently trusted, versioned documentary
integration, **not local configuration**. It ships the package schemas, fourteen
domain documents, issuer-current projection rules, evidence/environment pins,
and bounds (10,000 records, fan-in 32, payload 1,000,000 bytes; read budgets
64 roots/rules/source resolutions and 32 explanation paths). Sensitive domain
fields still fail the signed non-sensitive ceiling. No protected deployment is
claimed.

`space.Config.Profile` is trusted application code. Replay invokes it after every
verified policy transition and before each authenticated transaction candidate;
the local write path invokes the same function. Grants are re-derived solely
from that exact verified policy. Rejected policy versions never become authority.
Kernel `Configure` preserves already admitted history and protected captures;
historical admission facts are used only while validating configuration and are
never installed as current grants. `Fork` copies that admitted state and its
private bindings without re-admitting historical records under a later policy.
Dynamic snapshots are storage/debug data: restore by verified Git replay, never
by treating the cached snapshot as independently trusted `NewState` intake.

For each candidate the profile supplies a deterministic scanner review. This
means only that the configured offline scan found no prohibited content/size; it
does not certify truth or absence of secrets. Lineage is always **unknown**, with
an incomplete deterministic integration fact and no asserted inputs. A submitter
cannot manufacture complete lineage from its envelope. Self declarations bind
only registered identities to themselves. There are no implicit third-party
representations, authority receipt events, declassification decisions, corpus
coverage declarations, external source resolvers or publication-currentness
attestations. In particular this integration cannot admit an authoritative
`decision_record` without independently trusted receipt integration. It does not
silently upgrade a documentary observation into an external decision. Records
from a different intake profile that cannot reproduce this profile's admission
output remain diagnostics.

This provisional choice and distribution of trusted profile configuration outside
tests remain an [unresolved integration question](../UNRESOLVED_QUESTIONS.md).
The genesis pin is an out-of-band trust anchor supplied by the caller. Changing
that anchor means choosing another trust root, not obtaining a grant by editing
local configuration.

## Closed output and data boundary

JSON is one UTF-8 object and newline. The exact envelope keys are:

```json
{"type":"result","command":"recall","data_classification":"data","data":{"cursor":"memory:1:...","spaces":[]},"error":null}
```

An error uses `type: error`, the same command/classification keys, and
`error: {code: STRING, exit: INTEGER}`. `data` is null unless verified partial
results are deliberately returned (check failures, currentness conflicts or
rewritten history). Short fixed-code diagnostics also go to stderr. No Git stderr,
rejected record body, key seed or private signer material is included.

The closed `data` variants are:

| Commands | Exact data keys |
| --- | --- |
| `version` | `version` |
| `keys init/show` | `identity`, `key_id`, `algorithm`, `public_key` |
| `spaces list` | `spaces` (closed config-space entries defined above) |
| `spaces add/init/show` | `id`, `policy`, `policy_digest`, `cursor`, `diagnostic_count`, `diagnostics` |
| `keys register`, `policy grant/revoke` | `commit`, `space` (the preceding summary shape) |
| `sync/check` | `spaces` (summary array) |
| `recall/explain/changes` | `cursor`, `spaces`; each space has `id`, `cursor`, `views`, `diagnostics` |
| `add/revise/assess/promote` | `id`, `version`, `commit`, `cursor`, `receipt`; scan error data has only `findings` |
| `conformance --json` | `report` (ordered existing report lines) |

`policy` is the closed `space.Policy` payload. A diagnostic has exactly `commit`,
`path`, `code`. A view follows the package's closed view schema with the single
top-level `authorized_snapshot_handle` omitted. Each item follows its closed
item shape, adds `data_classification: data`, `write_token: STRING|null` and
`source: {space: ID, cursor: COMMIT, refs: VERSION-REFS}`, and omits only the fresh
`authorized_snapshot_handle` from each `support`/`oppose` channel. Ref fields,
issuer, perspective, source references and every evaluation qualification remain.
Empty scopes are omitted to avoid exposing hidden subjects or scope counts.

Kernel reads still mint fresh, independent, uniform handles. The CLI does not
publish these capabilities or replace them with hashes/cursors. The output is a
stable **data projection**, not a reusable authorization ticket. Identical synced
state and logical query inputs produce byte-identical JSON; time-dependent
freshness can legitimately change when the logical clock crosses a boundary.

Compact output is the same qualified object on one line prefixed **`memory data:`**.
All record strings remain JSON quoted/escaped in both renderings, including
newlines and control characters. Instruction-like content cannot escape onto a
bare instruction line. Every item remains attributed data; consumers must never
execute or adopt text as authority. Both polarity records retain premise quality,
source state, freshness, coverage, qualification and dependency limits.

## Exit codes

| Exit | Meaning and representative codes |
| ---: | --- |
| 0 | Success |
| 2 | Usage/input selection: `usage`, `missing_config`, `unknown_space` |
| 3 | Typed refusal: kernel/sign/adapter code, e.g. `not_authorized`, `identity_mismatch`, `invalid_configuration`, `no_verified_policy` (including a wrong genesis pin), `invalid_cursor`, `unauthorized_owner`, `unknown_rule`, `record_not_found` |
| 4 | `history_rewritten`; cursor is preserved; reads return last verified views with this error |
| 5 | `verification_failed` from `check`, with exact diagnostic codes such as `invalid_signature` |
| 6 | Internal/IO/tool failure: `internal`, `config_io`, `git_failed`, `cache_io`, `record_io`, `policy_io` |
| 7 | `currentness_required`: an exact dependency is `ambiguous_current`, has both witnesses present, or has incompatible current assertions, under `--require-current` (also `conflicts`) (§10) |

Legacy `conformance` retains exit 1 for semantic disagreement and 2 for harness or
usage errors; JSON mode wraps either as `conformance_failed`. Legacy plain
`version` retains its one-line output.

## Git and validation tools

Git receives `os.Environ()` explicitly and unchanged: no hidden credential,
author, signing, config, protocol or agent overrides. Callers must arrange their
own Git environment, including clearing unrelated `GIT_DIR`/`GIT_WORK_TREE`
bindings. Every write and owner policy commit uses `git commit -S`, is verified before a
normal feature/space branch push, and has no unsigned production switch. A failed
signature restores only the command's own policy path; a racing push returns
`version_conflict` and moves HEAD, index and working tree to the last verified
head using a normal detached switch. Its signed unpublished attempt remains only
in reflog. Pre-existing dirty work is refused without overwriting it.

CLI tests build the binary once per package and execute subprocesses with isolated
homes and local bare remotes. SSH signing keys are ephemeral test-owned files;
explicit child environments disable host/system Git configuration, key agents
and network transports. `ssh-keygen` generates those fixture keys and verifies
real signed commits. Write tests include two registered homes reaching a real
pre-push barrier from the same parent, every typed refusal with publication-state
checks (including HEAD/index/tree equality with the verified cursor), read-bound
token and two-home prior-read/NFF regressions, raw scanner-output redaction,
session excerpts, receipt retries, promotion
read/write gates and quoted instruction-like data. Run `go -C go test ./cmd/memory`,
`go -C go test -race ./space ./cmd/...`, `go -C go vet ./...`,
`python3 spec/checks/validate.py`, and `go -C go run ./cmd/memory conformance`.
Go temp artifacts use `TMPDIR`; saved project logs belong under `.temp/`.

## Directory discovery and owner qualification

Pin only your own owner's platform genesis out of band, using manual `spaces add`.
The namespace is the prefix of genesis owners (`a/agent:owner` gives `a`), not the
space ID. A foreign platform pin cannot become your directory. Wholly unqualified
single-owner legacy platforms remain supported, with unqualified identities only.
Named platform readers must possess a key registered in its current policy;
listing or a binding never creates a reader grant in the listed space.

```sh
memory directory advertise --space a/project:example --out advertisement.json
memory directory publish --space a/platform:shared --entry advertisement.json
memory directory list --space a/platform:shared
memory spaces add a/project:example --from-directory a/platform:shared
memory recall '*' --space a/project:example
memory spaces update a/project:example --from-directory a/platform:shared
memory directory withdraw --space a/platform:shared --space-id a/project:example
```

For another owner's target, that owner exports the advertisement and our platform
owner publishes the file. Each signature has its own purpose and authority.
`--bindings FILE` is a JSON array of closed `{kind: "identity"|"project", id: STRING}`
pairs, sorted by kind then ID with no duplicates. Project advertisements default
to one project binding of their space ID; agent/platform advertisements default
to `[]`. Agent identity is never inferred from a space name. `list`/`show` expose
these lookup keys as data; they grant no access and carry no keys.

Advertisement generation copies ID, kind, genesis, configured remote/branch and
the observed verified policy. Discovery verifies the target's complete policy
chain, the exact observed policy floor and its owner's signature before saving
anything. Metadata/signature/anchor mismatches give `directory_mismatch`.
Different existing pins give `genesis_conflict`; add of an existing same pin gives
`duplicate_space`. Update changes location only, refuses dirty clones, and retains
the first-parent cursor guard (`history_rewritten`). Neither call silently re-pins.

Only SSH/HTTPS target locations are accepted. Explicit file transport is for
isolated tests (`GIT_ALLOW_PROTOCOL=file`). Option-shaped URLs, helpers such as
`ext::`, and control characters refuse `directory_transport` before target Git.
New add/update calls refuse `directory_withdrawn` or `directory_stale` when the
publisher is no longer a current platform owner. Previously configured targets
keep syncing their own pins; `sync`/`check` report a `directory_diagnostic` without
revoking access or failing those commands solely for the directory warning. Unsharing requires target reader revocation **and** Git access
revocation. A still-listed target after reader revocation gives `not_authorized`.

Every registration/grant identity in an owner-qualified policy must be qualified
(`identity_owner_mismatch`). A local owner may register `b/agent:reader` and grant
it reader access to owner `a`'s space. The signature attests this association;
raw `--public-key` bytes have no origin metadata and cannot expose false owner
attribution. Mixed owner namespaces refuse `mixed_owner_namespace`; foreign writer
grants refuse `cross_owner_writer`. No guest writes, forward rights, federation,
expiry or automatic Git ACL management are introduced.

After losing a home, recreate/recover the identity key and obtain any needed
owner-signed replacement registrations, manually pin the own-owner platform,
then discover target pins again. Recovery does not restore a lost temporary key
or bypass current reader authorization.

## Exact conflict checks and resolver policy

`explain ID --require-current [--task T --step STEP]` checks that exact dependency.
Without `--version`, it evaluates the current selected versions and skips
historical versions of that ID; explicit `--version N` checks that exact version.
Ordinary explain still discloses authorized history. `recall '*' --subject S
--schema X [--schema-version N] --require-current` selects exact opaque subject
and schema IDs (schema version defaults to 1). Do not use substring recall as a
precise dependency check: an unrelated matching record can otherwise stop work.
The flags select existing authorized views; they create no grants.

Exit 7 (`currentness_required`) means `ambiguous_current`, both support and oppose
witnesses `present`, or a current/last-received assertion with non-empty
`incompatible_with`. Only that dependent step stops. Exit-7 read output preserves
`data.cursor` and `data.spaces`, adding `data.escalation`. No conflict exits 0.
Use a fresh exact check to resume, never board-task closure alone. A separately
issued ruling requires explicitly repointing the dependency and checking that
its issuer is among the original packet's resolvers; an arbitrary fresh assertion
from another writer does not meet that resume rule.

`conflicts --space S --id ID [--task T --step STEP]` returns the packet directly
in `data`: empty `conflicts` and exit 0, or a non-empty list and exit 7.
`conflicts --ref SPACE:ID:VERSION --ref OTHER_SPACE:OTHER_ID:VERSION ...` returns a
caller-reported packet and exit 7, even when the kernel detects no conflict.
Repeated refs are deduplicated. The final colon delimits the positive decimal
version; configured space IDs delimit the prefix, leaving record IDs opaque.
A spelling that matches more than one configured space prefix is refused with
usage (2), never guessed. Use unambiguous configured IDs for this form.
A hidden/unreadable ref and a missing ref both give `record_not_found` (3), with
no partial packet even if other supplied refs are visible. Mixed `--ref` and
`--space`/`--id` forms refuse. These are pure reads apart from normal verified Git
sync and its local cursor/cache updates: no memory record, board task or
notification is written and the only process started by memory is Git.

The closed packet schema is
[`go/escalation/escalation.schema.json`](../go/escalation/escalation.schema.json),
format `swarma-memory-escalation/1`, `data_classification: "data"`. Its fields are:

```text
{format, data_classification, reporter, dependent:{task,step}, conflicts:[{
  conflict_key, kind, space, commit, policy:{version,digest},
  items:[{ref,subject,schema,issuer,currentness}],
  evidence:{support,oppose,incompatible_with}, area, resolvers, resolver_basis
}]}
```

Task and step are optional opaque caller IDs, otherwise null. Items contain only
references and metadata; evidence arrays contain authorized explanation root
assessment/justification refs for each matching literal, not text or the full
proof closure. All evidence is restricted to the reporter's authorized explain.
There are no content, excerpt or prose fields. Unknown fields are rejected at
every nesting level. Treat all strings as inert data, never executable instructions.
The formatter additionally checks nonempty IDs, positive versions, commit/digest
syntax and sorted unique recipient/evidence lists, using the existing kernel
schema validator's supported closed-object subset.

A key is `sha256:` plus the lowercase SHA-256 of canonical JSON
`{"kind":K,"items":[{"space":S,"ref":{"id":ID,"version":N}},...]}`.
Deduplicate and sort the ref set by space, ID, then numeric version. Reporter,
time, cursor and policy are excluded. Detected conflicts use one block/key per
(space, item or item set, kind): ambiguity includes all disclosed candidates;
incompatibility includes the item and its incompatible peer refs. Distinct
conflicts in a recall have independent keys. A `reported` packet uses one shared
key over its full cross-space ref set and one block per distinct (space, route),
where route is `(area,resolvers,resolver_basis)`. Blocks contain only that route's
items and sort by `(space,conflict_key)`, with a canonical tie-break for routes.
The orchestrator reuses one open resolver task per key and unions recipients
across that key's blocks. Cross-owner routes remain information; file only on
your own owner's board. Memory never contacts a board.

New signed policies carry `format: "swarma-memory-policy/2"`. This versions the
payload schema; the signature framing purpose remains `swarma-memory-policy/1`.
Legacy payloads omit `format` and `match`; verification preserves those exact
canonical signed bytes. A new owner transition upgrades to v2. Legacy free-text
areas route as a single catch-all union of identities, never by interpreting
area prose; the upgrade names this entry `legacy`. Unqualified legacy recipients
are reported as `resolver_warnings` by `spaces show` (field omitted when empty).
An invalid upgraded legacy entry must be corrected/removed in the new policy;
verification of the historical legacy signature is unaffected.

```text
memory policy resolvers set --space S --area queue-design --schemas '[{"id":"schema:assumption","version":1}]' --subjects '["topic:queue"]' --identities '["owner/agent:resolver"]'
memory policy resolvers remove --space S --area queue-design
memory policy resolvers show --space S
```

All three commands require a registered current owner. Set replaces the unique
area label, or adds it; omitted `--schemas`/`--subjects` mean empty arrays (any).
The CLI sorts the JSON arrays; duplicates refuse. Each v2 entry requires closed
`match:{schemas:[VersionRef],subjects:[string]}`, sorted unique arrays and
non-empty sorted unique identities. Matching is exact schema AND subject;
one both-empty catch-all is allowed. Two overlapping non-catch-all entries or
two catch-alls refuse with `resolver_overlap`, at signing and verification.
Schema refs must be accepted. Each resolver needs a registered key, an explicit
reader grant and a writer grant in the same policy and namespace, otherwise
`resolver_unqualified`. A public grant does not qualify a named resolver. A
foreign reader cannot become a resolver. Failed edits publish nothing and prior
policy routing remains in force. No matching route falls back to owners with
`default_owners`; other bases are `named` and `catch_all`. Routing grants no powers.

Issuers can revise/withdraw their own records and assessments. An issuer's revision preserves
the target's subject and perspective; another issuer's challenge retains the
challenger's own perspective. Assessments accept `--perspective own|team`
and `--perspective-principal ID`, like assertion writes; cross-issuer evidence
must explicitly target the same team perspective to qualify under this profile.
A non-issuer resolver issues its own ruling in its own sequence; the caller must
repoint and recheck. The original remains attributed. The Git profile has no
authority events: `ambiguous_current` and canonical deciding-authority receipts
are tested only with kernel vectors and test-profile snapshots. Receipt
integration is out of scope; ordinary attributed decisions are not receipts.
