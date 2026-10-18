# Memory CLI: foundation, administration and reads

Build `go build -o bin/memory ./cmd/memory`. The application embeds the public
package schemas and domain documents and runs outside the source checkout.
`conformance` retains its repository-root working-directory contract.

## Home and config

`--home DIR` (any argument position) overrides `MEMORY_HOME`. Either selects one
directory for config, keys, clones and caches. Otherwise config and the temporary
identity key live under `$XDG_CONFIG_HOME/swarma-memory` (default
`$HOME/.config/swarma-memory`), and clones/caches under
`$XDG_STATE_HOME/swarma-memory` (default `$HOME/.local/state/swarma-memory`).
The home must be outside Git working/bare repositories and metadata directories, including symlink aliases.

`config.json` has exactly `identity`, `key_file`, and `spaces`; its closed
[schema](../cmd/memory/config.schema.json) is enforced on load. Each space has
exactly `id`, `remote`, `branch`, `clone_path`, `cache_path`, `genesis_digest` and
`kind` (`agent`, `project`, `platform`). Clone/cache names are SHA-256 encodings
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
| `spaces show ID` | Sync and return verified policy, digest, cursor and diagnostics |
| `keys register --space ID --identity ID --public-key BASE64` | Current owner endorses a key in a new signed policy version |
| `policy grant --space ID --identity ID --role reader\|writer` | Current owner replaces that identity's role grant in a new version |
| `policy revoke --space ID --identity ID --role reader\|writer` | Current owner removes that role grant in a new version |
| `sync [--space ID]` | Fetch/verify configured spaces and advance verified cursors |
| `check [--space ID]` | Same verification, with exit 5 if any diagnostics exist |
| `recall QUERY [--rule issuer_current] [--require-current]` | Case-insensitive substring search over authorized structured assertion content; `*` selects every authorized assertion |
| `explain ID [--version N]` | Kernel explanation for authorized assertion versions, including historical versions when explicitly selected |
| `changes [--since CURSOR]` | Kernel view changes from a protected replay baseline; omitted baseline means initial view |
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
impersonate a registered reader. A signed `public` reader grant uses the public
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

Writes `add`, `revise`, `assess`, and `promote` remain the next task. They can use
the same home loader, signer, `agentprofile` and `space.Repository.Write` seam.

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
| `conformance --json` | `report` (ordered existing report lines) |

`policy` is the closed `space.Policy` payload. A diagnostic has exactly `commit`,
`path`, `code`. A view follows the package's closed view schema with the single
top-level `authorized_snapshot_handle` omitted. Each item follows its closed
item shape, adds `data_classification: data` and
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
| 7 | `currentness_required`: a matching item is `ambiguous_current` or has admissible support and opposition, under `--require-current` (§10) |

Legacy `conformance` retains exit 1 for semantic disagreement and 2 for harness or
usage errors; JSON mode wraps either as `conformance_failed`. Legacy plain
`version` retains its one-line output.

## Git and validation tools

Git receives `os.Environ()` explicitly and unchanged: no hidden credential,
author, signing, config, protocol or agent overrides. Callers must arrange their
own Git environment, including clearing unrelated `GIT_DIR`/`GIT_WORK_TREE`
bindings. Every owner policy commit uses `git commit -S`, is verified before a
normal feature/space branch push, and has no unsigned production switch. A failed
signature restores only the command's own policy path; a racing push returns
`version_conflict`, retaining the signed local attempt for inspection.

CLI tests build the binary once per package and execute subprocesses with isolated
homes and local bare remotes. SSH signing keys are ephemeral test-owned files;
explicit child environments disable host/system Git configuration, key agents
and network transports. `ssh-keygen` generates those fixture keys and verifies
real signed commits. Run `go test ./cmd/memory`,
`go test -race ./space ./cmd/...`, `go vet ./...`,
`python3 spec/checks/validate.py`, and `go run ./cmd/memory conformance`.
Go temp artifacts use `TMPDIR`; saved project logs belong under `.temp/`.
