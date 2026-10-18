# Unresolved integration questions

The [in-memory trust layer](docs/signing-policy.md) makes its signing, chain and
verification contracts explicit. Later integration owners need to resolve:

| Architecture section | Question | Current boundary |
| --- | --- | --- |
| §5.3 | Is multi-owner threshold approval required for policy changes? | One authorized owner signature suffices; no threshold is implied. |
| §5.3 | What actions implement owner retirement/revocation for persistent git spaces? | Signed retention metadata records `retain` or `deny`; this task performs neither action. |
| §5.3 / §6.3 | How are the genesis digest and trusted kernel/domain intake configuration distributed/authenticated? | Explicit trusted caller inputs; the git adapter now derives in-force policy position and anti-rollback cursors from first-parent history. Registry distribution remains future integration. |

The [git-space decisions](docs/git-spaces.md#architecture-decisions-and-limits) document
first-parent policy forks, authenticated transaction metadata, sequence projection,
per-space views and cursor/rebuild boundaries. The directory meaning of reader
space metadata and operational retirement remain future-stage questions.

The broader design questions remain listed in [architecture §15](docs/architecture.md#15-open-questions).
