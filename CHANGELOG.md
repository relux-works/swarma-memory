# Changelog

## 0.3.1-draft — readers-first attributed revision

- Accept atomic `revise.auxiliaries` source/justification proposals with closed
  shape, reference, authority, CAS, receipt and replay checks.
- Keep attributed CLI emission disabled by one build-time constant until the
  reader upgrade gate is complete; source flags return `feature_not_enabled`.
- Report module and VCS provenance in `memory version` and stable JSON.
- Use readable skill idempotency keys, with session coordinates in source metadata.
- Preserve the 0.3.0 read profile and schema namespace. Old readers reject the new
  write variant; see [spec release history](spec/RELEASES.md) for rollout limits.
