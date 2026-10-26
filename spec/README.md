# Bounded evidence memory — specification package

Version: **0.3.1-draft**. Status: decided design, not an implemented or
security-qualified service. All examples are synthetic or admitted non-sensitive
architecture examples. There are **53 normative clauses and 86 conformance
vectors: 78 semantic and 8 protected-deployment checks**.

The 0.3.0 schema namespace and read profile remain stable; see [RELEASES.md](RELEASES.md)
for the reader-first rollout of the optional write extension.

The complete implementation contract is here. No design document, private
system, network lookup or external library is required to interpret it.
[COVERAGE.md](COVERAGE.md) maps every vector to the normative clauses it
exercises. The kernel is portable; the adapter is a separate consumer contract.

| Artifact | Purpose |
| --- | --- |
| [RELEASES.md](RELEASES.md) | Version history |
| [kernel/semantics.md](kernel/semantics.md) | Normative meanings, algorithms, authorization vocabulary, operation order, refusal codes and fixture execution |
| `kernel/schemas/` | Fourteen JSON Schema 2020-12 documents, including one additional schema for a reusable fixture corpus |
| `kernel/vectors/semantic/` | S01–S54, P01–P15 and nine reclassified boundary cases |
| `kernel/vectors/deployment/` | B04–B06, B09–B11, B16–B17; enforcement requires a real protected deployment |
| [domains/decisions/README.md](domains/decisions/README.md) | Decision, rule, assumption and explicit proposal schemas; archive-home → delete-home fixture |
| [domains/profiles-synthetic/README.md](domains/profiles-synthetic/README.md) | Eight requested profile schemas plus explicit hypothesis and released-city variants |
| [adapters/swarma.md](adapters/swarma.md) | Swarma platform bindings, authority boundaries and data-only delivery |
| [checks/validate.py](checks/validate.py) | Stdlib structural, reference, coverage, normalization and hygiene checks, including bounded violation controls |

Run from the containing repository directory:

```sh
python3 spec/checks/validate.py
```

It requires only Python 3.10 or later and the standard library. It parses every
JSON file with duplicate-key and numeric checks, verifies closed schemas, resolves
only package URN references, validates every vector and domain document, checks
initial-state references, exercises forbidden predicates and pair normalization,
and checks unique vector and normative-clause coverage. Exit 0 means these
**structural package checks passed**. It does not evaluate evidence, authenticate
real policy facts, exercise live storage or certify protected deployment behavior.

`build_schemas.py` and `build_vectors.py` are deterministic authoring aids. They
write only package schemas, domain documents, the reusable fixture corpus and vector JSON;
expected evidence results are explicitly hand-specified, not computed by an
evaluator. To reproduce those artifacts:

```sh
python3 spec/checks/build_schemas.py
python3 spec/checks/build_vectors.py
python3 spec/checks/validate.py
```

Python 3 is the only required project tool. The checker prints its report to
stdout and writes nothing. Authoring outputs stay under this package; no packages,
processes, services or network connections are installed or started.

An independent evaluator must implement all five records, the exact domain
meta-schema, three projection families, two evidence channels, deterministic
bounded walk, currentness, freshness, disclosure and the modeled operation
transitions. It must execute each complete vector snapshot and operations,
compare every response and postcondition after only its declared normalization,
and ensure every forbidden predicate is false. Extra output fields fail the closed
schema. Admission stamps, source cuts, lineage and resource accounting stay in the
protected binding, not the response. The fixture format is an internal test
interface: numeric cuts and capture indices are not public capabilities.

Semantic conformance requires all 78 semantic vectors to pass under the named
profile, including modeled erasure and delivery transitions. A narrower read-only
implementation must declare unsupported operations and cannot claim complete
profile conformance. An implementation that admits writes through a separate path
and exposes only reads must not claim adversarial isolation. A protected
implementation additionally needs the 8 deployment cases exercised against real
authentication, delivery, storage, restore, control and execution boundaries, with
its admitted numeric limits and availability policy recorded. Running a simulator
on deployment JSON is not that qualification. No deployment results are claimed
by this package.

The five-record kernel neither adopts a decision nor publishes a profile.
Publication, matching, contact consent and execution remain outside it. The
synthetic profile examples authorize no admission of real personal data; that
still requires the separately qualified protected service and owner policy.

The normative prose defines field meaning and ordering; schemas define closed
wire shape; vectors pin concrete results. A contradiction between them is a
package defect and blocks a conformance claim: an implementer must not silently
choose the most convenient artifact. A change to an expected result requires a
reviewed profile revision. Deployment inputs (real source classes and retention,
production resource limits and restore, identity and authority bindings, permitted
availability disclosure) are outside this package; no unresolved semantic input is
required to execute the supplied vectors.
