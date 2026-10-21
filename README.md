# swarma-memory

Agent memory for the Swarma platform: **bounded evidence memory**.

Agents replace one another: sessions restart, tasks move to other workers, accounts retire. Memory keeps the knowledge that would otherwise be lost — why a decision was made, what depends on it, which arguments were already checked and rejected — separately from the agents that produced it. It stores typed assertions with their sources, justifications, assessments and revisions, and answers which admitted evidence supports or opposes a precisely scoped assertion, from whose perspective and at which moment.

Memory reports evidence, not truth, and grants no authority: a record about yesterday's grant does not permit today's action. It reaches agents only as data, never as instructions.

## Status

The Go kernel implements the complete stage 1 semantic model: atomic writes, bounded evidence reads, disclosure, publication checks and erasure/restore accounting. The signing/policy trust layer, write scanner and git-space library adapter are implemented. This repository holds:

- [`spec/`](spec/README.md) — the normative specification package (draft 0.3.0): the kernel semantics, 14 closed JSON Schemas, the decisions and synthetic profiles domain packages, the Swarma adapter contract and 85 conformance vectors (77 semantic, 8 protected-deployment). The Go evaluator matches all 77 semantic vectors; independent cross-evaluator agreement was established for the earlier 66-vector corpus; the deployment vectors require a real protected deployment and are not qualified.
- The Go module in [`go/`](go/): package boundaries, the kernel interface, strict JSON intake, canonical bytes and digests, closed-schema validation, and a semantic conformance runner/CLI. All 77/77 semantic vectors, 79/79 admission results and all six inventories match. See [write admission](docs/write-admission.md), [read evaluation](docs/read-evaluation.md) and [disclosure and erasure](docs/disclosure-erasure.md) for APIs, scope and validation. These are semantic model results; the eight protected-deployment vectors remain unqualified. The [CLI](docs/cli.md) implements private homes, signed owner administration, verified sync/check, multi-space reads and `add`, `revise`, `assess`, `promote` writes with receipts, session excerpts and bounded retries. The root Curator skill packages this CLI for agents. The first working version's design is in [docs/architecture.md](docs/architecture.md).

The stage-2 [signing and policy API](docs/signing-policy.md) provides immutable canonical records, purpose-separated Ed25519 signatures, temporary per-identity keys, closed signed policies and owner-endorsed registries, authenticated policy chains and a verified kernel snapshot adapter. The [git-space adapter](docs/git-spaces.md) adds authenticated first-parent admission replay, immutable storage, bounded write retries, scans before signing, external anti-rollback cursors and multi-space reads. The CLI uses this adapter for all write commands. [Unresolved integration questions](UNRESOLVED_QUESTIONS.md) identify the remaining owner decisions.

## Design in brief

- **Small kernel.** Five record kinds (assertion, source reference, justification, assessment, revision) and a computed view. Everything domain-specific is schemas on top.
- **Spaces.** Memory is a set of spaces — agent, project, platform — each a git repository with a policy file. A view is computed over the spaces the caller may read.
- **Autonomous, signed writes.** Agents write memory themselves. Every record is signed over its canonical bytes; every reader verifies signature, schema, space policy and revision authority before using it.
- **Honest evaluation.** For support and for opposition separately: whether a witness was found and whether the evaluation completed. A missing source or an exhausted budget is never refutation.
- **Order of decisions** comes from the deciding issuer's own ordered events, never from arrival time.
- **Provenance and erasure.** Derived records inherit the disclosure constraints of all their inputs; erasure follows content lineage, not the reasoning graph.
- **Portability.** The kernel's semantic contract does not depend on Swarma; the same normalized inputs give the same answer anywhere.

## Build and test

Tools: Go 1.25 or later for the CLI, vet and tests; Python 3.10 or later for the specification checker. Both use only their standard libraries. The module is in `go/`; the commands below run from the repository root.

```sh
go -C go build -o ../bin/memory ./cmd/memory
./bin/memory version
./bin/memory conformance # exits 0: 77/77 semantic vectors pass
go -C go vet ./...
go -C go test -timeout=30m ./...
python3 spec/checks/validate.py
```

The binary goes to the ignored `bin/` directory. Vet, tests and the checker report to the terminal; Go's build and test caches use its configured cache directory. Optional saved logs belong in the ignored `.temp/` directory. CI runs the same vet, test and specification checks on pushes and pull requests. Semantic conformance and both full ratchets are mandatory CI checks.

The `kernel` input boundary exposes `DecodeJSON`, `CanonicalJSON`, `DigestJSON` and `LoadSchemas`. Decoded trees use `int64` integers, never `float64`. Schema loading takes an `io/fs.FS`; tests supply `os.DirFS` for the package schemas. `Schemas.Validate` checks structure against an exact loaded package URI; `Schemas.ValidateRecord` also checks assertion domain references against caller-supplied exact `SchemaRef` versions. `Schemas.ValidateStoredRecord` shares domain-content checks with admission for the signing/verification boundary; it does not perform authority or expected-version admission. `NewState` and `State.Write` add domain-content validation, authenticated intake, retention checks, atomic batches, replay and issuer-local revision authority. `State.Read` and the typed `Kernel` reads evaluate authorized views; `Capture` binds immutable history for `changes`.

The conformance command runs from any working directory using embedded schemas, semantic vectors and ratchets. An optional vectors directory selects a different semantic suite: `memory conformance <vectors-dir>`. It prints one verdict per vector and a summary, exits 0 only if all vectors pass, 1 on conformance failures, and 2 on harness/input errors. The 8 deployment vectors remain out of scope. Malformed, empty or mixed-profile suites are harness errors.

`conformance.Load` accepts an `io/fs.FS` and loaded kernel schemas. Executors receive independent copies of the initial snapshot, operations and query, without the expected report. `Compare` preserves typed JSON, ordered results and exact timestamps, checks forbidden predicates against actual values, and normalizes only declared handles. Oracle acceptance and mutation controls exercise all applicable semantic vectors; they establish comparator behavior, not kernel evaluation or statistical randomness. `go/conformance/passing.txt` lists required passing vector IDs (77 required vectors); `go/conformance/passing-ops.txt` lists all 79 matching admission results. Both ratchets reject regressions, duplicates or unknown entries and report newly passing IDs. The CLI also prints operation and inventory agreement; [write admission](docs/write-admission.md) explains partial-result handle checks; there are no admission exclusions.

## Curator skill

The repository root is the skill root: [`SKILL.md`](SKILL.md) and
[`agent-skill.json`](agent-skill.json). Curator builds `memory` from `go/cmd/memory`
using the closed `go-v1` driver with `go/` as the build root, then owns the
`bin/memory` artifact and project/global command shims. The package selects no
flags, toolchain, output path, hooks or generators. The Go 1.25 module is
stdlib-only, so it needs neither a vendor tree nor a `modules` declaration.
The operator must supply a trusted toolchain supporting Go 1.25; Curator's
protocol minimum alone (Go 1.23) does not satisfy this module's requirement.

Check the package with `curator skill check . --json` in the selected Curator
environment. Installation is through that environment's project Skillfile;
no real agent profile is wired by this repository. See
[architecture §12](docs/architecture.md#12-skill-and-installation).

Committed inputs in `go/assets/` are exact copies of the normative schemas,
domain schemas (excluding test fixtures) and semantic vectors in `spec/`, plus the Go conformance ratchets.
After changing those sources, run `python3 -B .scripts/sync-assets.py` and
`go -C go test ./assets`. CI rejects drift or added/missing files. The installed
binary's default `memory conformance` works without a source checkout. An explicit
vector directory still resolves from the caller's cwd; deployment vectors remain
out of scope.

The complete layout replay is `python3 -B .scripts/relayout.py`. Copy the
committed `.scripts/` directory into a clean, disposable pre-layout clone first.
Recovery from an interrupted run is a fresh clone; rerunning is not recovery. The
exchange replaces the checkout directory itself: invoke it from the parent as
`python3 -B CHECKOUT/.scripts/relayout.py`, with no shell cwd inside the checkout.
The entrypoint classifies all root inputs before moving every Go source directory
into `go/` and keeps root package files together in `go/assets/`. It rewrites
all module imports (including the root package) and paths, applies the
committed context patch for CLI/embed/CI/docs/skill changes, then syncs assets.
The complete prospective result is built in a sibling staging directory, then
published by one atomic directory exchange (macOS/Linux support is required).
The explicit keep-list retains normative sources, documentation and packaging.
Unclassified inputs, collisions, patch conflicts and asset-sync failures leave
the original path set, bytes and modes unchanged. Existing ignored output/temp
and Git metadata entries move intact at publication, without traversal or copying;
publication errors restore them. Staging requires write access to the parent and
the same filesystem. Patch conflicts stop for review instead of replacing
upstream files. Reruns are idempotent. `.scripts/move-go-module.py` is only the mechanical phase.

`python3 -B .scripts/relayout.py --check BASE` replays twice in ignored scratch
and requires exact file-set, byte and executable-mode equality with committed
`HEAD` (`--expected TREE` selects another Git tree). Use the pre-layout base
commit for `BASE`. `python3 -B .scripts/relayout-test.py BASE` exercises the
additional `extra/` package and `e2e/` importer on a synthetic newer base,
upstream edit preservation, repeat replay, full-entrypoint patch/unclassified/
mid-sync refusals, publication rollback and
check-mode drift detection. Run full validation after replaying onto a new base.

## Write scan

`scan.Scan(value, scan.Limits{MaxCanonicalBytes: ..., MaxStringBytes: ..., MaxArrayLength: ...})` checks the canonical JSON tree from `kernel.DecodeJSON` (or a root `kernel.Record`). It returns `nil` or typed findings sorted by JSON Pointer, then detector. All three scanner limits are inclusive; string length counts UTF-8 bytes, including object keys. Zero is a real cap; negative limits refuse. The git-space write path invokes it before signing admitted records and persisted intake context/idempotency metadata.

The offline detectors cover AWS access-key IDs, GitHub classic/fine-grained and OAuth tokens, Slack tokens, Stripe keys, Google API keys, OpenAI/Anthropic-style keys, compact JWTs, Bearer values, URL passwords and PEM private-key headers (including OpenSSH and incomplete blocks). Hex candidates of at least 32 bytes require Shannon entropy ≥3.0 bits/byte; base64/base64url candidates require at least 32 unpadded bytes and ≥4.5 bits/byte. These heuristics catch obvious cases and never prove absence of secrets. They make no network calls.

Entropy exemptions are narrow: complete UUIDs; lowercase 64-hex output digests at `/output_digest`, `/declassification/output_digest` and `/body/declassification/output_digest`; source digest values at `/digest/value` and `/body/digest/value` only with `algorithm: sha256-cjson-v1` or `sha256-bytes-v1`; exact `sha256:<64 lowercase hex>` locators at `/locator`, `/object`, `/body/locator` and `/body/object`; and exact kernel 32-lowercase-hex handles at `/receipt_handle`, `/authorized_snapshot_handle` and their `/body` equivalents. The root body paths support scanning bodies alone. The same hash in ordinary content is still checked. Exemptions never suppress size or known-format detectors.

Every excerpt is fully `[REDACTED]`. Findings for unsafe object keys and their descendants use the nearest safe ancestor JSON Pointer with `PointerRedacted: true`; `InKey` identifies findings in keys. Locations conservatively hide any segment that is itself part of a detected string or credential component, plus every matching fragment of at least four bytes, including reconstruction across path segments and RFC 6901 escaping. The entire flagged string is protected, including PEM payloads after a header-only match. Redaction stops before the first contributing segment; `OriginalDepth` records only the original segment count, not a reversible or unique identifier. Benign paths remain exact, but shared text can intentionally cause a more conservative ancestor/root fallback. Run `go -C go test -v ./scan` for synthetic detector/near-miss controls, raw-output redaction, exact size boundaries and the corpus false-positive check (every initial record and body in the semantic vectors and domain fixtures).

## Tools

| Tool | Purpose and entry point | Output |
| --- | --- | --- |
| Go 1.25+ | `go -C go build -o ../bin/memory ./cmd/memory`, `go -C go vet ./...`, `go -C go test -timeout=30m ./...` | Binary in ignored `bin/`; diagnostics in terminal |
| Write scan tests | `go -C go test -v ./scan` | Detector controls and corpus finding counts in terminal |
| Memory CLI | `bin/memory --home DIR keys init --identity ID`; [read/write/admin command reference](docs/cli.md); `go -C go run ./cmd/memory conformance [vectors-dir]` | Private config/key, clones/caches in the selected home; data-only JSON or prefixed compact output |
| CLI integration tests / SSH signing | `go -C go test ./cmd/memory`, `go -C go test -race ./space ./cmd/...`; tests invoke `ssh-keygen` with ephemeral keys and isolated Git configuration | One subprocess binary per package, temporary homes and local signed bare repositories under `TMPDIR` |
| Git | `space.Clone`, `Repository.Sync` and `Repository.Write` use `git clone`, `fetch`, `rev-list`, `ls-tree`, `cat-file`, signed `commit` and `push`; exercise with `go -C go test -race ./space` | Caller-selected space clone and external index; isolated repositories in tests |
| Conflict escalation | `memory explain ID --require-current`, `memory conflicts --space S --id ID`, `memory policy resolvers set\|remove\|show --space S ...`; `go -C go test -count=1 -timeout=30m -run TestStage6 ./e2e` | Closed data-only packets in command output; isolated signed Git fixtures under `TMPDIR`; see [CLI](docs/cli.md#exact-conflict-checks-and-resolver-policy) |
| Platform directory | `memory directory advertise/publish/list/show/withdraw`, `memory spaces add/update ID --from-directory PLATFORM`; `go -C go test ./cmd/memory ./space -run TestDirectory` | Signed advertisement files, immutable platform entries, private verified clones/caches and data-only diagnostics; see [CLI](docs/cli.md#directory-discovery-and-owner-qualification) |
| Git-space gates | `go -C go test -race ./space` | Isolated temporary bare repositories/clones and external test indexes under the Go test temp directory; verdicts in terminal |
| Trust-layer tests | `go -C go test ./space ./sign/...` (ephemeral keys only) | Diagnostics in terminal; temporary key files under the Go test temp directory |
| Curator | `curator skill check . --json`; `curator install PROJECT` using the project's declared source | Managed context/shims in the selected environment; binary/build receipts in manager-owned state |
| Asset sync / identity gate | `python3 -B .scripts/sync-assets.py`; `go -C go test ./assets` | Committed `go/assets/`; exact bytes/file-set checks in terminal |
| Complete layout replay | `python3 -B .scripts/relayout.py`; `python3 -B .scripts/relayout.py --check BASE`; `python3 -B .scripts/relayout-test.py BASE` | Relocated module and complete packaging patch; exact-tree comparison and controls in ignored scratch |
| Stage-4 agent gate harness | `.scripts/stage4-gate/prepare SCRATCH SOURCE`; `.scripts/stage4-gate/verify SCRATCH TOPIC TEXT`; `.scripts/stage4-gate/self-test SCRATCH SOURCE` ([launch recipe and evidence limits](.scripts/stage4-gate/README.md)) | Fresh scratch Curator install, local signed space, agent env files and JSON evidence under `SCRATCH`; starts no agents |
| Python 3.10+ | `python3 spec/checks/validate.py` | Structural specification checks in terminal |

Optional validation logs and scratch artifacts go in ignored `.temp/`.

## Checking the specification

```sh
python3 spec/checks/validate.py
```

Python 3.10 or later, standard library only. Exit 0 means the structural package checks passed; it does not evaluate evidence.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
