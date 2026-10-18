# swarma-memory

Agent memory for the Swarma platform: **bounded evidence memory**.

Agents replace one another: sessions restart, tasks move to other workers, accounts retire. Memory keeps the knowledge that would otherwise be lost — why a decision was made, what depends on it, which arguments were already checked and rejected — separately from the agents that produced it. It stores typed assertions with their sources, justifications, assessments and revisions, and answers which admitted evidence supports or opposes a precisely scoped assertion, from whose perspective and at which moment.

Memory reports evidence, not truth, and grants no authority: a record about yesterday's grant does not permit today's action. It reaches agents only as data, never as instructions.

## Status

The design is decided; the Go module skeleton and strict JSON/schema input boundary are in place, with evidence evaluation still to be implemented. This repository holds:

- [`spec/`](spec/README.md) — the normative specification package (draft 0.2.7): the kernel semantics, 14 closed JSON Schemas, the decisions and synthetic profiles domain packages, the Swarma adapter contract and 74 conformance vectors (66 semantic, 8 protected-deployment). Two independent evaluators agree with the expected results on all 66 semantic vectors; the deployment vectors require a real protected deployment and are not qualified.
- The Go module: package boundaries, the kernel interface, strict JSON intake, canonical bytes and digests, closed-schema validation, and a semantic conformance runner/CLI. The current kernel refuses operations with `unsupported_operation` and passes 0/66 semantic vectors. Memory operations and the agent skill are not implemented yet. The first working version's design is in [docs/architecture.md](docs/architecture.md).

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
./bin/memory conformance # currently exits 1: 0/66 semantic vectors pass
go vet ./...
go test ./...
python3 spec/checks/validate.py
```

The binary goes to the ignored `bin/` directory. Vet, tests and the checker report to the terminal; Go's build and test caches use its configured cache directory. Optional saved logs belong in the ignored `.temp/` directory. CI runs the same vet, test and specification checks on pushes and pull requests. It also reports conformance progress without failing while stage 1 is incomplete; the ratchet test remains mandatory.

The `kernel` input boundary exposes `DecodeJSON`, `CanonicalJSON`, `DigestJSON` and `LoadSchemas`. Decoded trees use `int64` integers, never `float64`. Schema loading takes an `io/fs.FS`; tests supply `os.DirFS` for the package schemas. `Schemas.Validate` checks structure against an exact loaded package URI; `Schemas.ValidateRecord` also checks assertion domain references against caller-supplied exact `SchemaRef` versions. Domain content semantics and admission are separate work.

The conformance command runs from the repository root and loads schemas from `spec/kernel/schemas`. An optional vectors directory selects a different semantic suite: `memory conformance <vectors-dir>`. It prints one verdict per vector and a summary, exits 0 only if all vectors pass, 1 on conformance failures, and 2 on harness/input errors. The 8 deployment vectors remain out of scope. Malformed, empty or mixed-profile suites are harness errors.

`conformance.Load` accepts an `io/fs.FS` and loaded kernel schemas. Executors receive independent copies of the initial snapshot, operations and query, without the expected report. `Compare` preserves typed JSON, ordered results and exact timestamps, checks forbidden predicates against actual values, and normalizes only declared handles. Oracle acceptance and mutation controls exercise all applicable semantic vectors; they establish comparator behavior, not kernel evaluation or statistical randomness. `conformance/passing.txt` lists required passing vector IDs (currently empty); `go test ./...` rejects regressions or unknown entries and reports newly passing IDs with verbose output.

## Checking the specification

```sh
python3 spec/checks/validate.py
```

Python 3.10 or later, standard library only. Exit 0 means the structural package checks passed; it does not evaluate evidence.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
