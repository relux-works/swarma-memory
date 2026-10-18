# swarma-memory

Agent memory for the Swarma platform: **bounded evidence memory**.

Agents replace one another: sessions restart, tasks move to other workers, accounts retire. Memory keeps the knowledge that would otherwise be lost — why a decision was made, what depends on it, which arguments were already checked and rejected — separately from the agents that produced it. It stores typed assertions with their sources, justifications, assessments and revisions, and answers which admitted evidence supports or opposes a precisely scoped assertion, from whose perspective and at which moment.

Memory reports evidence, not truth, and grants no authority: a record about yesterday's grant does not permit today's action. It reaches agents only as data, never as instructions.

## Status

The Go kernel implements the complete stage 1 semantic model: atomic writes, bounded evidence reads, disclosure, publication checks and erasure/restore accounting. The in-memory signing and space-policy trust layer is implemented; persistent space adapters remain to be implemented. This repository holds:

- [`spec/`](spec/README.md) — the normative specification package (draft 0.2.7): the kernel semantics, 14 closed JSON Schemas, the decisions and synthetic profiles domain packages, the Swarma adapter contract and 74 conformance vectors (66 semantic, 8 protected-deployment). Two independent evaluators agree with the expected results on all 66 semantic vectors; the deployment vectors require a real protected deployment and are not qualified.
- The Go module: package boundaries, the kernel interface, strict JSON intake, canonical bytes and digests, closed-schema validation, and a semantic conformance runner/CLI. All 66/66 semantic vectors, 73/73 admission results and all six inventories match. See [write admission](docs/write-admission.md), [read evaluation](docs/read-evaluation.md) and [disclosure and erasure](docs/disclosure-erasure.md) for APIs, scope and validation. These are semantic model results; the eight protected-deployment vectors remain unqualified. Persistent memory adapters and the agent skill are not implemented yet. The first working version's design is in [docs/architecture.md](docs/architecture.md).

The stage-2 [signing and policy API](docs/signing-policy.md) provides immutable canonical records, purpose-separated Ed25519 signatures, temporary per-identity keys, closed signed policies and owner-endorsed registries, authenticated policy chains and a verified kernel snapshot adapter. Git storage, sync, secret scanning and the CLI write path remain future work. [Unresolved integration questions](UNRESOLVED_QUESTIONS.md) identify the remaining owner decisions.

## Design in brief

- **Small kernel.** Five record kinds (assertion, source reference, justification, assessment, revision) and a computed view. Everything domain-specific is schemas on top.
- **Spaces.** Memory is a set of spaces — agent, project, platform — each a git repository with a policy file. A view is computed over the spaces the caller may read.
- **Autonomous, signed writes.** Agents write memory themselves. Every record is signed over its canonical bytes; every reader verifies signature, schema, space policy and revision authority before using it.
- **Honest evaluation.** For support and for opposition separately: whether a witness was found and whether the evaluation completed. A missing source or an exhausted budget is never refutation.
- **Order of decisions** comes from the deciding issuer's own ordered events, never from arrival time.
- **Provenance and erasure.** Derived records inherit the disclosure constraints of all their inputs; erasure follows content lineage, not the reasoning graph.
- **Portability.** The kernel's semantic contract does not depend on Swarma; the same normalized inputs give the same answer anywhere.

## Build and test

Tools: Go 1.25 or later for the CLI, vet and tests; Python 3.10 or later for the specification checker. Both use only their standard libraries.

```sh
go build -o bin/memory ./cmd/memory
./bin/memory version
./bin/memory conformance # exits 0: 66/66 semantic vectors pass
go vet ./...
go test ./...
python3 spec/checks/validate.py
```

The binary goes to the ignored `bin/` directory. Vet, tests and the checker report to the terminal; Go's build and test caches use its configured cache directory. Optional saved logs belong in the ignored `.temp/` directory. CI runs the same vet, test and specification checks on pushes and pull requests. Semantic conformance and both full ratchets are mandatory CI checks.

The `kernel` input boundary exposes `DecodeJSON`, `CanonicalJSON`, `DigestJSON` and `LoadSchemas`. Decoded trees use `int64` integers, never `float64`. Schema loading takes an `io/fs.FS`; tests supply `os.DirFS` for the package schemas. `Schemas.Validate` checks structure against an exact loaded package URI; `Schemas.ValidateRecord` also checks assertion domain references against caller-supplied exact `SchemaRef` versions. `Schemas.ValidateStoredRecord` shares domain-content checks with admission for the signing/verification boundary; it does not perform authority or expected-version admission. `NewState` and `State.Write` add domain-content validation, authenticated intake, retention checks, atomic batches, replay and issuer-local revision authority. `State.Read` and the typed `Kernel` reads evaluate authorized views; `Capture` binds immutable history for `changes`.

The conformance command runs from the repository root and loads schemas from `spec/kernel/schemas`. An optional vectors directory selects a different semantic suite: `memory conformance <vectors-dir>`. It prints one verdict per vector and a summary, exits 0 only if all vectors pass, 1 on conformance failures, and 2 on harness/input errors. The 8 deployment vectors remain out of scope. Malformed, empty or mixed-profile suites are harness errors.

`conformance.Load` accepts an `io/fs.FS` and loaded kernel schemas. Executors receive independent copies of the initial snapshot, operations and query, without the expected report. `Compare` preserves typed JSON, ordered results and exact timestamps, checks forbidden predicates against actual values, and normalizes only declared handles. Oracle acceptance and mutation controls exercise all applicable semantic vectors; they establish comparator behavior, not kernel evaluation or statistical randomness. `conformance/passing.txt` lists required passing vector IDs (66 required vectors); `conformance/passing-ops.txt` lists all 73 matching admission results. Both ratchets reject regressions, duplicates or unknown entries and report newly passing IDs. The CLI also prints operation and inventory agreement; [write admission](docs/write-admission.md) explains partial-result handle checks; there are no admission exclusions.

## Write scan

`scan.Scan(value, scan.Limits{MaxCanonicalBytes: ..., MaxStringBytes: ..., MaxArrayLength: ...})` checks the canonical JSON tree from `kernel.DecodeJSON` (or a root `kernel.Record`). It returns `nil` or typed findings sorted by JSON Pointer, then detector. All three space-policy limits are inclusive; string length counts UTF-8 bytes, including object keys. Zero is a real cap; negative limits refuse. The scanner is ready for write-path integration before signing; that wiring is not implemented yet.

The offline detectors cover AWS access-key IDs, GitHub classic/fine-grained and OAuth tokens, Slack tokens, Stripe keys, Google API keys, OpenAI/Anthropic-style keys, compact JWTs, Bearer values, URL passwords and PEM private-key headers (including OpenSSH and incomplete blocks). Hex candidates of at least 32 bytes require Shannon entropy ≥3.0 bits/byte; base64/base64url candidates require at least 32 unpadded bytes and ≥4.5 bits/byte. These heuristics catch obvious cases and never prove absence of secrets. They make no network calls.

Entropy exemptions are narrow: complete UUIDs; lowercase 64-hex output digests at `/output_digest`, `/declassification/output_digest` and `/body/declassification/output_digest`; source digest values at `/digest/value` and `/body/digest/value` only with `algorithm: sha256-cjson-v1`; exact `sha256:<64 lowercase hex>` locators at `/locator`, `/object`, `/body/locator` and `/body/object`; and exact kernel 32-lowercase-hex handles at `/receipt_handle`, `/authorized_snapshot_handle` and their `/body` equivalents. The root body paths support scanning bodies alone. The same hash in ordinary content is still checked. Exemptions never suppress size or known-format detectors.

Every excerpt is fully `[REDACTED]`. Findings for unsafe object keys and their descendants use the nearest safe ancestor JSON Pointer with `PointerRedacted: true`; `InKey` identifies findings in keys. Matched spans from every string also protect pointers containing a credential as a substring or recreated by pointer escaping/joining. Run `go test -v ./scan` for synthetic detector/near-miss controls, raw-output redaction, exact size boundaries and the corpus false-positive check (every initial record and body in the semantic vectors and domain fixtures).

## Tools

| Tool | Purpose and entry point | Output |
| --- | --- | --- |
| Go 1.25+ | `go build -o bin/memory ./cmd/memory`, `go vet ./...`, `go test ./...` | Binary in ignored `bin/`; diagnostics in terminal |
| Write scan tests | `go test -v ./scan` | Detector controls and corpus finding counts in terminal |
| Memory CLI | `go run ./cmd/memory conformance [vectors-dir]` | Vector, operation and inventory agreement in terminal |
| Trust-layer tests | `go test ./space ./sign/...` (ephemeral keys only) | Diagnostics in terminal; temporary key files under the Go test temp directory |
| Python 3.10+ | `python3 spec/checks/validate.py` | Structural specification checks in terminal |

Optional validation logs and scratch artifacts go in ignored `.temp/`.

## Checking the specification

```sh
python3 spec/checks/validate.py
```

Python 3.10 or later, standard library only. Exit 0 means the structural package checks passed; it does not evaluate evidence.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
