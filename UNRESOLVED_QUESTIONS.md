# Unresolved integration questions

The [in-memory trust layer](docs/signing-policy.md) makes its signing, chain and
verification contracts explicit. Later integration owners need to resolve:

| Architecture section | Question | Current boundary |
| --- | --- | --- |
| §5.3 | Is multi-owner threshold approval required for policy changes? | One authorized owner signature suffices; no threshold is implied. |
| §5.3 | What actions implement owner retirement/revocation for persistent git spaces? | Signed retention metadata records `retain` or `deny`; this task performs neither action. |
| §5.3 / §6.3 | How are the genesis digest, trusted domain registry and exact in-force policy position distributed/authenticated? | Explicit trusted caller inputs; git history, anti-rollback cursors and registry integration are future tasks. |

The broader design questions remain listed in [architecture §15](docs/architecture.md#15-open-questions).
