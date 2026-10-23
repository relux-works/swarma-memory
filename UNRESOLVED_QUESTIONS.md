# Unresolved integration questions

The [in-memory trust layer](docs/signing-policy.md) makes its signing, chain and
verification contracts explicit. Later integration owners need to resolve:

| Architecture section | Question | Current boundary |
| --- | --- | --- |
| §12 | Does the owner confirm the repository-root skill and `go/` module layout? | Reversible packaging decision: the non-dot, contained build root is one stdlib-only module; root normative spec is copied into checked embedded assets. No real profile activation. |
| §6.3 / §8 | where trusted kernel configuration comes from outside tests | Provisional built-in `agentprofile`: public schemas/domains, documentary intake with unknown lineage, no external authority facts, policy-derived in-force grants. See [CLI](docs/cli.md#provisional-trusted-profile). Profile distribution/version negotiation and independently authenticated external receipt integration remain unresolved. |
| §5.3 / §6.3 | How should identity-key removal and P-256 signing work? | SSH-agent Ed25519 and additive file-to-agent rotation are implemented. No key removal/revocation command or P-256 backend exists; neither is implied by rotation. |
| §5.3 | Is multi-owner threshold approval required for policy changes? | One authorized owner signature suffices; no threshold is implied. |
| §5.3 | What actions implement owner retirement/revocation for persistent git spaces? | Signed retention metadata records `retain` or `deny`; this task performs neither action. |
| §5.3 / §6.3 | How are the genesis digest and trusted kernel/domain intake configuration distributed/authenticated? | Explicit trusted caller inputs; the git adapter now derives in-force policy position and anti-rollback cursors from first-parent history. Registry distribution remains future integration. |

The [git-space decisions](docs/git-spaces.md#architecture-decisions-and-limits) document
first-parent policy forks, authenticated transaction metadata, sequence projection,
per-space views and cursor/rebuild boundaries. The directory meaning of reader
space metadata and operational retirement remain future-stage questions.

The broader design questions remain listed in [architecture §15](docs/architecture.md#15-open-questions).
