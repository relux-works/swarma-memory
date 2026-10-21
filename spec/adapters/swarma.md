# Swarma adapter contract — 0.3.0-draft

This contract binds the portable kernel to the Swarma platform. It does not change
any platform module. The kernel remains portable and owns only its
admitted record history. The kernel requires identical normalized semantic results
for the same normalized tuple (corpus, exact schema/rule versions, perspective, authorized projection, cut and logical budget) without the dispatcher, board or session host.

The adapter MUST implement the kernel contract by clause id, not by adding
platform interpretations to record kinds. Documentary, embedded and protected
profiles may differ in authentication/isolation guarantees, never in the meaning
of complete, incomplete, conflicted premises, stale, current or unavailable.

| Binding | Adapter obligation | Authority it must not replace |
| --- | --- | --- |
| Principal and issuer | Bind each opaque kernel principal (issuer, subject, submitter) to a platform identity cell id: the spendable cell that holds the current keys, a hash of the next keys and a parent reference. Resolve the cell's state through the owner registry, the sole authoritative writer of identity state before the chain launches, from a signed snapshot within its freshness bound. Bind the account generation the cell currently points to. Preserve the original issuer independently of the authenticated submitter. How the cell id is derived (for example, a hash of its first record) does not change this binding. | Owner registry and the identity cell's own spending history; user manager for account generation and retirement |
| Submitter | Set from authenticated intake; ignore client attempts to supply protected submitter or recorded fields. | Transport authentication and current admission policy |
| Representation | A representation_ref names an exact grant record in the owner registry. At admission, resolve it against the registry snapshot and check issuer cell, submitter cell, generation, scope, relation, expiry and that neither the grant nor either cell is spent into a terminal state. Record the checked grant reference and snapshot; do not maintain an independent delegation registry. Failure, including an unresolvable or stale snapshot, is representation_invalid; an unavailable registry is never an implied grant. | Owner registry (grants) |
| Key rotation | A rotation spends the identity cell with its next keys and is effective from publication. Records admitted before the rotation keep their identity and history; their signatures verify against the keys current at their admission. Rotation never re-issues, re-signs or reorders memory records. | Owner registry and identity consensus |
| Revocation | Spending a grant revokes the representative; spending an identity cell into a terminal cell revokes the identity. Later admissions under it refuse. Existing records stay as history. A terminal issuer's current-state projections are reported as stale until the projection rule names a successor; memory never infers one. | Owner registry |
| Space and audience | Bind space to an existing policy scope; evaluate separate read, use, retain, forward and write predicates and live revocations. Use per-audience subject/principal aliases for publication. | Existing broker/trust and disclosure-policy owners |
| Retention intent | Supply explicit context.retention_context for every storage operation, bound to its authenticated actor. Check exact current retain scope for every output and transitive known input, including same-batch and incomplete-lineage lower bounds. Preserve that intent for authorized replay; do not derive it from a later query or onward labels. | Existing storage/disclosure-policy owner; no new read/use/forward permission |
| Recorded sequence | Assign only memory's internal transaction sequence. Never equate it to a source sequence or expose it as a public cursor. | Each source's independent ordered ledger |
| Source owner and exact revision | Resolve through the owning system's approved read interface, with current rights. Preserve source owner, exact revision, provenance, original issuer and carrier. | Canonical source writer |
| Authority receipt | Verify against the deciding authority's canonical record and predecessor order. A mirror, signed delivery or memory reviewer cannot mint adopted/accepted status. | Reviewed decision register or relevant board/domain decision authority |
| Evidence policy | Pin admitted check kinds, exact objects, rules, policy and environment. Model review remains semantic_review. | The named reviewer/check owner; existing execution authority |
| Source origin | Authenticate original root bindings so reimports, catalog copies and paraphrases cannot appear independent. | Original declarant and admitted source-binding authority |
| Custody and erasure | Register payload, index, summary, cache, export, diagnostic and qualified backup lineage. Bind erase receipt audience/purpose explicitly to its authenticated actor, filter metadata before fencing, and retain full protected closure. Fence before purge; keep restore closed until outside-domain evidence is reconciled. | Each custody owner, including external recipients |

The following source distinctions are mandatory:

- User-manager account generation and retirement records are evidence, never a
  current grant by themselves. Broker credentials, grants, leases and revocations
  remain with their owners; no secrets enter memory.
- Dispatcher admission/execution/cleanup receipts must be cited canonically. A
  board activity mirror or an agent's report proves only its attributed report.
- Session-host logs, delivery/application receipts and input fences may enter
  only via admitted exports. Memory gets no native handles, stdin, restoration
  authority or shared writable context files.
- Board goals, task status and accepted candidates remain board/domain authority.
  Memory challenges or revisions do not alter those records.
- Keeper obligation custody is distinct from identity-key custody and credential
  brokering. No deadline scheduler or second obligation ledger enters memory.
- a2a/bridge events prove only the sender/content/delivery guarantees actually
  provided. They do not prove fulfilled work or standardized A2A semantics.
- Curator and the approved launch-construction owner retain instruction, skill,
  profile and configuration authority. Memory changes none of them.

Delivery to agents is a **separate data-only block**, delivered through an explicit
tool result in the first slice. There is no automatic seeding or change to swarm-handoff/2. A later session-start mechanism must use the session host's owned data-input channel. The session-start
snapshot may stay fixed for that session to preserve cache behavior. Its contents
remain a historical view; current authorization, freshness and erasure are
rechecked before resolution or new delivery. A snapshot has no overlay weight.

The adapter's logical data frame has these fields; this table defines adapter
meaning, not an unauthorized extension of an existing platform wire schema:

| Field | Required value or meaning |
| --- | --- |
| classification | Literal `data` |
| semantic_profile | Literal `0.2.5-draft` |
| view | The closed kernel View, retaining every polarity field and item attribution |
| scope_binding | Protected binding to recipient, audience, purpose, source frontiers and policy; disclose only admitted metadata |
| provenance_binding | Protected per-item issuer, submitter, source owner/revision, class, qualification and lineage; retain attribution through every summary, expansion and reimport |
| delivery_binding | Owned delivery receipt reference; proves delivery only, not internal premise use |

The data frame MUST NOT become an instruction overlay, AGENTS.md content, skill
root, machine base context or a forged user turn. Signing the frame authenticates
its envelope and delivery; it does not upgrade enclosed text to authority. Every
summary and index must retain the data classification and original attribution.
Provenance labels are not claimed to defeat semantic prompt injection; unchanged
external authority gates are the enforceable boundary. An imperative in a signed
source remains data (B04).

`swarm-handoff/2` is closed. The adapter MUST NOT add knowledge_view, a new reference
kind, arbitrary seed injection or an implicit user-message wrapper. A host adapter
must use its existing protected tool-output/journal custody contract or an
explicitly owner-approved versioned schema extension. This document chooses no
unapproved wire extension and spells no harness flags. Optional memory data stays
separate from the authoritative current task/goal and host continuation package.

In git spaces, agents write records themselves; there is no approval gate. Every
record is signed by its submitter and every reader verifies signature, schema, the
space policy and revision authority before using it. Imported publications stay
attributed to their source and admission class; no writer creates adopted status
without the deciding authority receipt. No raw journal intake is permitted. A git
history is neither a private-data store nor an erasure mechanism. Synthetic profile fixtures do not authorize real personal intake.

The protected service is introduced only for a concrete need (sensitive data, guaranteed erasure or enforcement before write) and after its own qualification.
Before sensitive intake or autonomous writes, its owner must establish private
state and a sole writer, separate OS identity and mediator, authenticated peers and
current generations, authenticated server identity, published socket permissions,
admitted roles, independent read/use/retain/forward checks, and an owned service
egress row including the qualified DNS path and periodic verification. The
installer/operator applies that boundary; the dispatcher cannot silently edit it.
Memory must not borrow host/broker identity or treat a source URL as network
permission. Numeric limits and reservations follow the actual disclosure boundary
and reserve capacity for erasure and external controls.

The adapter MUST NOT crawl arbitrary locators, persist arbitrary transcripts,
execute candidate code, run tests, make model calls under memory identity, grant
rights, accept results, alter goals, wake sessions, enqueue work or modify source
journals. A request for fresh evidence returns execution_required data to the
existing authorized executor. Advisory changes do not trigger work. Stop, park,
revocation, recovery and acceptance remain independent of memory availability.
A business operation may require fresh evidence without blocking those controls.

For new session citations written with `--source-session runtime:session:message`,
the adapter binds `owner: runtime:<runtime>`, `object: session:<id>`,
`revision: message:<id>` or `index:<n>`, `provenance: reported`, and
`availability: unavailable`. Canonical locator JSON is the root `origin` for the
message (K-DISC-3). `digest.algorithm: sha256-bytes-v1` covers the exact UTF-8
**retained text, not necessarily the whole message**, without framing. A deleted
session leaves an independently admitted retained excerpt present. Kernel
K-SRC-1 supplies the authorized, citation-closed `sources` table; the adapter MUST
NOT reconstruct hidden source payloads from storage. Legacy locator/hash fields
remain valid and render as stored. This grants no live resolver or authority.

Publication is outside memory. A publisher uses an admitted audience_projection,
assigns its own publication id/revision and keeps the view link protected. It
must strip memory ids, hidden lineage, global cuts and private handle linkage.
Send-time checks are mandatory; prepared data is no standing permission. Revoke,
unpublish and erase are distinct. Independent delivered copies cannot be recalled
without their owner's supported disposition receipt. Unqualified retaining sinks
must be refused or explicitly excluded by the admitted custody policy before
sending; a memory signature grants no deletion authority over host evidence.

For B04–B06, B09–B11, B16 and B17, a deployment report MUST record the exact service
version, policy, identity generation, audience, source pins, admitted limits,
actual boundary stimulus, observed response and external effects. It must test
actual transport, filesystem/custody, restore, delayed writer, reservation and
control behavior. Merely returning the fixture's desired harness observation is
not evidence. B16's observations must come from the actual independent stop/park/
revocation paths; B17 must observe that no candidate execution was launched.
Semantic results and deployment results are reported separately. Timing and
traffic-analysis isolation require their own named tests and are not claimed here.

For v0.2 the adapter computes content lineage from controlled inputs, never merely from model citations: exact reads for deterministic transformations and all context/tool results/recalled views supplied to a model call within the declared integration profile. Unknown completeness remains unknown and is not publishable. Declassification assessments record each constrained owner's exact decision; the effecting component checks all decisions again before each new disclosure. A revoked snapshot stays historical data; memory does not restart or re-prompt the session. An audience owner's exclusion changes only that named projection.
