# Changelog

## Unreleased

- Preserve full Matrix source coordinates and exempt only closed artifact-source
  locator shapes from entropy checks, including enabled attributed revision;
  retain named-token and strict free-text checks. Reject malformed Matrix session
  coordinates as value-free usage errors before admission.
- Avoid entropy false positives from complete task-ID path segments beside short
  engineering text, retaining original checks for long residual candidates.

## 0.2.0 — CLI attributed revision enabled

- Enable source-bearing `replace` and `correct` after the reader-first upgrade.
  Replacement, revision, source and documentary basis share one atomic write.
- Keep the single build-time constant as the emission rollback switch and test
  its `feature_not_enabled` refusal before input or writes.
- Document available attributed revise commands with readable retry keys.

## 0.3.1-draft — readers-first attributed revision

- Accept atomic `revise.auxiliaries` source/justification proposals with closed
  shape, reference, authority, CAS, receipt and replay checks.
- Keep attributed CLI emission disabled by one build-time constant until the
  reader upgrade gate is complete; source flags return `feature_not_enabled`.
- Report module and VCS provenance in `memory version` and stable JSON.
- Use readable skill idempotency keys, with session coordinates in source metadata.
- Preserve the 0.3.0 read profile and schema namespace. Old readers reject the new
  write variant; see [spec release history](spec/RELEASES.md) for rollout limits.
