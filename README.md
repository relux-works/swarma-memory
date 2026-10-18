# swarma-memory

Agent memory for the Swarma platform: **bounded evidence memory**.

Agents replace one another: sessions restart, tasks move to other workers, accounts retire. Memory keeps the knowledge that would otherwise be lost — why a decision was made, what depends on it, which arguments were already checked and rejected — separately from the agents that produced it. It stores typed assertions with their sources, justifications, assessments and revisions, and answers which admitted evidence supports or opposes a precisely scoped assertion, from whose perspective and at which moment.

Memory reports evidence, not truth, and grants no authority: a record about yesterday's grant does not permit today's action. It reaches agents only as data, never as instructions.

## Status

The design is decided; the Go module skeleton is in place, with kernel semantics still to be implemented. This repository holds:

- [`spec/`](spec/README.md) — the normative specification package (draft 0.2.7): the kernel semantics, 14 closed JSON Schemas, the decisions and synthetic profiles domain packages, the Swarma adapter contract and 74 conformance vectors (66 semantic, 8 protected-deployment). Two independent evaluators agree with the expected results on all 66 semantic vectors; the deployment vectors require a real protected deployment and are not qualified.
- The Go module skeleton: package boundaries, the kernel interface, and a `memory version` CLI. Memory operations, the conformance runner and the agent skill are not implemented yet. The first working version's design is in [docs/architecture.md](docs/architecture.md).

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
go vet ./...
go test ./...
python3 spec/checks/validate.py
```

The binary goes to the ignored `bin/` directory. Vet, tests and the checker report to the terminal; Go's build and test caches use its configured cache directory. Optional saved logs belong in the ignored `.temp/` directory. CI runs the same vet, test and specification checks on pushes and pull requests.

## Checking the specification

```sh
python3 spec/checks/validate.py
```

Python 3.10 or later, standard library only. Exit 0 means the structural package checks passed; it does not evaluate evidence.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
