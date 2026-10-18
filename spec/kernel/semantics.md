# Bounded evidence memory 0.2.6-draft

This document and the closed schemas and vectors are one contract. MUST, MUST NOT,
REQUIRED, SHALL, SHALL NOT, SHOULD and MAY have their RFC 2119 meanings. A heading
beginning `K-` is a stable normative clause. No other paragraph adds a requirement.

## Model and encoding

### K-SCOPE-1 — Evidence, not authority

The implementation MUST answer only which admitted evidence supports or opposes
an attributed assertion. It MUST NOT infer truth, permission, adoption, execution,
or a negative witness from absence. There are exactly five stored record kinds;
a view is derived data. The normalized input tuple consists of the admitted
corpus, exact schema and projection-rule versions, perspective, authorized
projection (including current policy facts), evaluation cut and logical budget.
Identical tuples MUST give equivalent semantic outputs in every deployment
profile, modulo only the fresh opaque-handle normalization in K-NI-2. Different
rights or cuts are different inputs and carry no equivalence promise. The tuple
includes every query parameter affecting those components: consumption `now`,
valid_at, mode, freshness override and rendering operation are not normalized away.

### K-JSON-1 — Closed input

JSON MUST be UTF-8, without duplicate keys, non-finite numbers, floating-point
numbers or unpaired Unicode surrogates. Unknown fields, variants and versions
MUST be refused. Object keys are compared by Unicode scalar value; strings are
not case-folded or Unicode-normalized. Arrays are ordered except where a clause
explicitly calls them sets. All set arrays MUST be duplicate-free and sorted by
canonical JSON of each element. Integers MUST be in [-9007199254740991,
9007199254740991]; versions and sequences MUST be positive; counters and bounds
MUST be nonnegative. References are exact `(id, version)` pairs, never fuzzy names.

### K-JSON-2 — Canonical bytes

`sha256-cjson-v1` means SHA-256 of UTF-8 JSON with sorted object keys, no optional
whitespace, unescaped non-ASCII scalar characters, and standard JSON escaping of
quotes, backslashes and control characters (lowercase hexadecimal escapes).
Integers use shortest decimal spelling, including zero instead of negative zero.
The framing bytes are the ASCII string `bounded-evidence:cjson-v1` followed by a
single zero byte and the canonical JSON. A digest MUST identify bytes only. An
output digest in a declassification pin covers the assertion body, before its
envelope is assigned. External references MUST be treated as data, never executed.

### K-ENV-1 — Envelope and identities

Every record MUST have every envelope field. `schema` MUST be an exact domain
schema for an assertion and null for other kinds. `subject`, `issuer`, `submitter`,
`perspective` and `space` MUST remain distinct. Ids are opaque strings in typed
namespaces; no parsing of an id grants authority. `(id, version)` is unique in a
snapshot. All output ordering is by `(id, numeric version)` unless stated otherwise.
`own` perspective MUST name the issuer; `observer` MUST name the observer issuer.
A team perspective requires an admitted issuer grant; it does not merge sequences.
An assertion with statement_kind or admission_class `self_declaration` requires
an exact trusted `(subject, principal=issuer)` entry in policy.subject_principals
and an own perspective naming that issuer. This adapter identity evidence is
independent of public aliases and of opaque ID spelling; even equal strings are
not proof without the binding. A valid representative changes only submitter,
never issuer, subject or perspective. Missing identity evidence or a different
subject yields `invalid_domain_value`; no coercion to another attribution is
permitted. Already-admitted snapshots obey the same invariant. An organisation's
statement about another subject uses an appropriate fact/assessment schema, not
that subject's self-declaration. P02/P10 cover own and delegated declarations;
P15 retains the organisation's separate fact sequence.


### K-ENV-2 — Authenticated intake

Proposals omit `submitter`, `recorded`, and `admission_class`; the authenticated
operation context supplies actor, time and class. The writer assigns successive
sequences starting above `runtime.memory_cut`, in proposal array order, and stamps
the context time. The actor becomes submitter. With unequal issuer and submitter,
the exact representation reference MUST match a currently valid policy fact for
issuer, submitter, space and operation/relation. Intake records `checked: true`.
An absent, invalid or expired representation MUST produce `representation_invalid`,
never a silent conversion into the submitter's own statement. With equal issuer
and submitter the representation reference MUST be null.

### K-ENV-3 — Admission classes and review

The four classes are `self_declaration`, `imported_publication`,
`machine_observation` and `semantic_inference`. Class is immutable provenance,
not assurance. A model-created statement MUST use `semantic_inference` and a
proposal or assessment-summary schema; a model check MUST be `semantic_review`.
Derivatives MUST preserve the originating classes in retained input envelopes;
their own class describes their own creation. The documentary profile requires
an explicit `allow` review fact for every proposed record. This fixture profile
also requires review facts in the other profiles, so automatic intake is not
implicitly authorized. Missing or quarantine review means `quarantined`.

### K-TIME-1 — Time and cuts

All timestamps MUST use UTC seconds `YYYY-MM-DDTHH:MM:SSZ`, with real calendar
values. Known validity is half-open `[from,to)`; null `to` is unbounded and any
non-null end MUST be strictly greater than the start. `unknown` has no invented
time. A point query excludes unknown validity; `valid_at: "any"` includes it and
preserves its label. `now` is the explicitly supplied consumption clock for freshness; it is independent
of valid_at and of the historical knowledge cut, including in hypothetical tests.
A query sees only records whose recorded sequence is at most
its memory cut, then applies revisions recorded by that cut. The source-cut vector
is a set of independently observed exact revisions, never a globally atomic cut.
In this draft, the query source-cut vector MUST equal the complete snapshot
runtime source-cut vector; any other frontier requires a separately supplied
snapshot and otherwise yields `invalid_time`. Source-access facts describe exact
source resolution at that frontier. An empty source-cut vector means use the
admitted exact references without claiming fresh external reads. Current disclosure and retention checks override
historical access. The runtime committed_cuts set lists readable atomic transaction boundaries.
A query cut MUST belong to that set: an intermediate sequence inside a batch is
`invalid_time` rather than a partially admitted snapshot. Each successful batch
adds only its final assigned sequence to committed_cuts. Future memory cuts are invalid; as-known cuts never see later
corrections even when the corrected validity starts earlier.

### K-REC-1 — Assertions and sources

An assertion MUST match the exact schema's statement kind and content fields.
Content is a field-name-sorted list of unique `{field,value}` pairs, with no extra
or missing required fields. A source MUST identify owner, kind, object, exact
revision, provenance, root origin and current availability. A direct declaration
is evidence of what its issuer stated, without requiring a document. Neither
source existence nor source integrity proves the assertion. An excerpt MUST have
its own retention-admission reference and a retain grant. A reference grants no
right to resolve or retain its bytes.

### K-REC-2 — Assessments and pins

An assessment is immutable. It MUST pin exact subject, check rule, evidence policy
and environment; `pass`, `fail`, and `indeterminate` are distinct. A mismatched
pin, expired assessment (`now >= usable_until`), wrong context, withdrawn check or
non-pass result MUST NOT qualify evidence. A root assessment additionally targets
an exact assertion and polarity, with the same subject pin. A rule certificate
targets the exact justification, has null literal target, matches its rule pin,
and is a passing deterministic `formal_entailment` assessment. A model claiming
any other check kind MUST be refused with `assessment_kind_invalid`.

### K-REC-3 — Evidence policy

Only the `root_kinds` named by the exact evidence policy can be roots. This draft
allows `semantic_review`, `test_result`, and `formal_entailment`; signature,
source_binding, account_control and declassification checks MUST NOT create
world-evidence roots. A human semantic review remains reviewer evidence. A
successful account-control check establishes only its pinned account-control
claim. Admission, source binding, origin binding and policy-owner decisions are
trusted input facts in semantic tests; deployment tests MUST establish their
actual authenticity separately. The kernel MUST NOT execute a check.

## Schemas, relations and revisions

### K-DOM-1 — Domain documents

Every domain document MUST satisfy the domain meta-schema. Field names MUST be
unique. `string`, `integer`, `boolean`, and `string_set` have exact JSON types
(boolean is not integer); string sets MUST be sorted unique strings and use set
equality; other fields MUST use exact equality. Two propositions are equal only
when schema version and all typed content fields are equal. Equivalence prose,
digests, and model similarity MUST NOT merge identities. Unknown domain versions
MUST yield `unknown_schema`, without falling back to a known version.

### K-DOM-2 — Cardinality and slots

A sequence key is issuer, subject, space, exact schema, perspective and slot.
For `single`, slot MUST equal canonical JSON of the slot-field values in the
schema's declared order (empty slot-fields give `[]`). `multi` MUST use slot `[]`
and includes the assertion id in its sequence key; distinct ids coexist. New
values are candidate replacements only: cardinality does not authorize overwriting.
An ordinary single sequence MUST NOT acquire a second live head by plain admission;
use a compare-and-set revision. Initial snapshots may contain competing receipted
branches of an external authority record as described by K-REV-3.

### K-DOM-3 — Cross-assertion incompatibility

A declared `unequal` relation MUST compare its named field only between current
assertions of the exact schema, the listed statement kinds, equal subject, space,
perspective and slot, with known overlapping valid intervals. All four scope
fields and `overlap: required` are mandatory in this draft. No rule means no
incompatibility. Comparison considers authorized current candidates with the same perspective,
including another issuer even when that issuer is not selected for item display.
The relation produces symmetric, sorted `incompatible_with`
references, distinct from signed evidence on an exact assertion. It MUST NOT
manufacture a root assessment, propagate a negative literal, or imply that either
assertion is false. A negative witness still requires K-EVAL-1. This conservative
separation avoids treating a competing unassessed statement as established
refutation. Competing proposals have no incompatibility rule in the supplied
domains. A model's possible-conflict review never creates this deterministic link.

### K-REV-1 — Revision authority and atomic compare-and-set

`replace`, `withdraw`, `correct` and `availability` MUST be issued by the target's
issuer or its checked representative. Any separately admitted issuer MAY
`challenge`; a challenge neither replaces nor withdraws its target. `revise`
MUST name the exact current head as `expected_version` for every non-challenge
relation. For ordinary records, the head is the latest active version; a
withdrawal or availability-only transition uses its revision reference as the
next compare-and-set token. Replacements/corrections use the replacement reference.
These tokens are derived from admitted revision order, not wall-clock time.
A mismatch or ambiguous head yields `version_conflict`, committing
nothing. A replacement/correction MUST preserve the sequence key, have the same
id and next version, and be committed atomically with its revision. New immutable
objects never overwrite old bytes. Two representatives racing from the same
head have one success and one conflict. Expected-version checks are performed
after exact idempotency replay detection and before checking whether the proposed
replacement id/version already exists.

### K-REV-2 — Revision effects

Withdrawal deactivates the target from its recorded transaction point and creates
no contrary evidence. Replacement/correction activates the new version and makes
the old one historical while preserving independent support paths. Correct may
backdate validity but never recorded knowledge. Availability revisions target
sources and override resolution state; they do not alter the original assessment
or assertion. A challenge is an attributed revision only. Any attempted mutation
of an external authority is outside the operation vocabulary.

### K-REV-3 — Authority currentness

A `decision_record` MUST cite a source whose policy authority-event fact is
canonical, issued by the deciding issuer, and admitted for the caller. Receipt
predecessor edges form a DAG. Within one decision slot, a candidate is current
iff no other eligible candidate's receipt strictly succeeds it in the deciding
issuer's order defined below. Two maximal
receipts produce `ambiguous_current` with both sorted candidates; arrival time
MUST NOT break the tie. Learned-late earlier events remain historical. A proposed
adopted record without that receipt is refused `authority_receipt_required`;
its author MAY explicitly submit a proposal under a proposal schema instead.
Importing a canonical receipt-bearing decision_record is exempt from the ordinary
single-head plain-admission restriction: the authority may supply historical or
incomparable events. Such import creates no memory-side replacement relation;
receipt ordering alone determines currentness. The id/version must still be new.
Memory-only revision links MUST NOT override receipt ordering or create adoption.

**Issuer-local canonical order.** After the existing canonical-event, receipt
eligibility and integrity checks, let `G = (V, E)` be the event graph, with edges
directed from each event to its declared predecessors. For deciding issuer `H`,
let `V_H` contain exactly events whose protected
`policy.authority_events[].issuer` is `H`, and let
`E_H = E intersect (V_H x V_H)`. Then `a ≺_H b` (written `a precedes_H b`) iff `(b, a)` is in
`E_H+`: a nonempty path from `b` to `a` using only those edges. Restrict the graph
before computing reachability; restricting only the endpoints of a global path
is not equivalent and MUST NOT be used. Every event on the path, including an
intermediate event with no assertion attached, counts. The source envelope's
issuer, submitter, carrier or catalog does not replace protected event issuer
attribution for this test.

One all-H path suffices. Cross-issuer edges establish no order for H; excluding
a foreign event MUST NOT contract its incoming/outgoing edges into a bypass.
Foreign branches MUST NOT cancel an existing all-H path. Mixed-issuer graphs
remain admissible subject to the existing integrity rules. Absence of a qualifying
path means order is not established, not that the state is invalid. Two otherwise
eligible unordered maxima therefore remain `ambiguous_current`, with neither
made historical merely by a mixed path. On admissible states, changes confined
to foreign parts of the graph with the H subgraph unchanged MUST NOT change
`precedes_H`. This invariant is about authority order, not every evidence field
that a foreign source might independently affect.

For an authoritative replacement/correction, the new canonical receipt MUST
strictly succeed the target's receipt under this same `precedes_H` relation;
equality is not succession. A missing qualifying receipt, including an identical,
prior or incomparable canonical receipt, MUST yield `authority_receipt_required`
with `retryable: false`, committing no records, cuts, dirty state or idempotency
entry. This requirement does not turn a receipt-order failure into a compare-and-set
failure: `version_conflict` remains the K-REV-1 current-head mismatch or ambiguity.
K-REV-1's exact successful replay detection still precedes the current-head check;
replaying an authorized completed replacement does not attempt a new succession.

### K-REV-4 — Three distinct conflict outcomes

`version_conflict` is only a refused write: nothing commits and no assertion,
assessment, opposite witness or dirty marker is created by the collision.
`ambiguous_current` is only a projection result for incomparable authoritative
candidates; it neither refuses their admission nor establishes opposition.
Evidence conflict means `witness: present` on both polarities of one exact
assertion, even if enumeration is incomplete. Both admissible witnesses remain.
APIs and renderers MUST preserve these three meanings separately. S02, S28 and
P14 provide the three distinct controls; no generic contradictory-state code
may replace them.

### K-RULE-1 — Closed finite graph

Justifications MUST be ground, finite and versioned, with nonempty premises.
Only registered assertion literals or source references are permitted. There are
no variables, default negation, quantifiers, callbacks, contraposition or implicit
completion. The sufficient-support graph between exact assertion versions MUST
be acyclic, including no self-edge, checked against the whole atomic batch.
Unknown references, cycles and cross-space premises without an authorized
separately admitted derivative MUST be rejected atomically. Social or entity
relations in ordinary content are not this graph.

### K-RULE-2 — Three edge roles

`documentary_basis` and `review_on_change` MUST use `declared_rationale` and null
check, and establish only attribution and registered review dependencies.
`sufficient_support` MUST use `checked_entailment`, assertion literals only, and
a valid K-REC-2 certificate; otherwise admission yields `rule_unqualified`.
Each premise list is AND; alternative rules for one signed conclusion are OR.
Rules are one-way. Contradiction neither explodes nor deletes an applicable path.
Rule applicability includes its validity, context, active revision and policy.

## Authorization and deterministic evaluation

### K-AUTH-1 — Policy before computation

A grant matches principal, space, audience, purpose and record id (`*` means all
records in that grant). Current runtime revocations override matching grants. Revocations are separate
immutable authorization events and MUST NOT rewrite the pinned policy revision.
Their exact principal/audience/purpose/right scope applies to every record and
space governed by that policy; this draft does not give a revocation a narrower
record or space selector. `retain` is independently revocable, like `read` and
`forward`. A retain revocation blocks new retention and authorized write replay;
it does not itself revoke another right or run an erasure job.
Read and use MUST both hold before a record contributes
to any query. Its disclosure must also include the query audience and purpose.
Metadata is disclosed only with `metadata: true`. This draft has no partial
content-only view shape: a record without that metadata grant is ineligible for
view computation. An authorized root with inaccessible named sources, or a rule
with an inaccessible certificate, is likewise filtered before logical accounting;
this is not a source-unavailable error about a hidden object. Write authorization requires an operation right for actor and space in at least
one admitted grant; it does not bypass per-record representation, review, retention
or disclosure checks. Erase and revoke additionally require the policy owner.
No matching read grant returns an
empty view, not an existence-dependent refusal. Purpose/recipient changes require
new authorization; views are not capabilities. Retain, forward, write, erase and
declassify rights are independent. A hidden premise makes its rule ineligible;
it MUST NOT consume logical budget, appear as a gap, or change any public field.
Evidence policy/version mismatch returns `policy_mismatch`. Projection/schema
lookup is against admitted public configuration, not a hidden-record oracle.

Every admit, admit_raw, revise and declassify context MUST supply
`retention_context: {audience, purpose}`. Its fixed principal is context.actor;
there is no principal override. For every proposed output and every transitive
known content input, retain MUST hold for that actor, that record's exact space
and id, and both fields of this one context. A matching grant may name `*` but
unrelated principals, spaces, records, audiences or purposes cannot supply it.
Check each record independently against current grants and revocations. The
operation right, read/use, metadata permission, a lineage fact, a representation
or a release assessment does not substitute for retain. Missing retain yields
`not_authorized` for the entire operation, with no partial writes.

This is a storage scope, independent of the output's onward disclosure labels.
Do not require retain in every labelled audience/purpose, and do not search
labels or a later query for any convenient granted scope. Empty disclosure
intersections can still be stored under an explicitly authorized retention
context; they remain non-disclosable. Retain alone grants no read, use, metadata,
forwarding or declassification permission. Existing deadlines and erasure
fences still apply; neither context nor a release widens them.

Retention is currently authorized only while the trusted intake `context.at`
is strictly earlier than every applicable non-null `retain_until`. Equality or
a later intake time MUST yield `not_authorized`, `retryable: false`, for the
whole write even with matching retain grants. A null deadline adds no bound.
Check the proposed outputs and every transitive known content input, including
incomplete-lineage lower bounds and same-batch inputs resolved by K-DISC-1.
An output's later or null deadline never widens an earlier input deadline.
This is part of current retention authorization before idempotency; it is not
`invalid_time`, because an expired but well-formed timestamp is not malformed.
Refusal performs no purge or other mutation of existing records or receipts.

### K-PROJ-1 — Projection grammar

Queries MUST name a versioned rule. `issuer_current` selects assertions by that
issuer and exact perspective. `observer_model` selects the named observer's
assertions and assessments; output items remain assertions, with assessments
reported as qualifications. `audience_projection` uses issuer-current selection
and additionally fixes the query audience and purpose to the rule's values.
A mismatch is `not_authorized`. Each selects the given space, subject, exact
schema, context and valid cut. An empty target list selects current heads; an
explicit target list selects those exact versions, preserving `historical`
labels. A withdrawn target is omitted. Dependencies may use other assertions in
the same authorized scope even if not selected for display. Perspective and
context MUST match throughout a witness. The kernel MUST NOT vote on a true model.

### K-PROJ-2 — Owner-selected exclusion

`excluded_refs` is a sorted set of exact assertion references in a named,
versioned `audience_projection`. Its admitted configuration is selected by the
space or audience owner, independently of the assertions' issuers. The other
two rule families MUST have an empty set. Exclusion removes those exact items
from that projection's selection and historical/review lists before producing
counts or metadata; it does not remove authorized premises of another selected
item. Such premise use still obeys disclosure and lineage rules. Excluded refs
MUST NOT be disclosed as removal reasons. Unknown refs in this filter have no
effect and MUST NOT reveal whether an unseen record exists.

A different exclusion set requires a new rule version; the query pins that
version. Exclusion creates no revision, withdrawal, negative witness, erasure
or external effect. The issuer's sequence and other projections remain intact.
If an owner separately erases a local copy, K-ERASE applies independently.

### K-EVAL-1 — Witness definition

For each selected exact assertion, support and opposition MUST be evaluated
independently. A witness is either an active, passing, in-policy assessment of
that literal, or an active qualified sufficient rule with witnesses for every
signed premise. Both present means conflict on that assertion. No roots and no
successful rule means `not_found`, never negative evidence. A result MUST preserve
both channels, including when a conflicted premise supports another assertion.
Source and documentary checks alone are not signed roots.

### K-EVAL-2 — Deterministic bounded walk

For each displayed assertion and each polarity, start independent root, rule and
source counters at zero. Depth-first evaluate the requested literal: eligible root
assessments first in reference order, then eligible rules in reference order;
visit each rule's premises sorted by (assertion id, numeric version, polarity,
with oppose before support). Memoize literals within that walk. Evaluate all
premises even if an earlier one fails. Visit all alternatives unless a bound is
hit. One eligible root assessment costs one root visit; one eligible rule costs
one rule visit; each distinct current-required source resolution costs one source
visit. Certificates, filtering and traversal of withdrawn or hidden candidates
cost no logical visits. Before a visit that would exceed its bound, skip that
candidate, mark the affected channel incomplete, and add the corresponding cutoff.
Continue other work still possible within bounds. A successful checked path may
therefore coexist with incomplete enumeration. A missed premise propagates
incompleteness upward; a known successful alternative does not erase it.

### K-EVAL-3 — Extended polarity record

Every polarity MUST include all fields in the view schema. `evaluation` describes
only the authorized registered walk, never source-corpus completeness.
`corpus_coverage` is `unknown` unless an authorized coverage declaration exactly
names the displayed assertion, in which case it is `declared` with that reference;
multiple declarations MUST be rejected as ambiguous input. `dependency_coverage`
is always `registered_only`. Qualifications are the sorted union of passing root
check kinds and rule-certificate `formal_entailment` for found paths. Root origins
are deduplicated, sorted, and counted; empty evidence gives zero and an empty list.
The authorized snapshot handle is the same as the containing view's handle.
A complete not-found channel is not a proof of corpus or world absence.

### K-EVAL-4 — Premise quality

A root witness is a clean path (it has no assertion premises). For each rule path,
recursively examine its premise paths and evaluate each premise's opposite literal
under an independent K-EVAL-2 walk. A present opposite taints that path; an
incomplete opposite search with no witness makes it unchecked. Existing taint
wins over unchecked status on the same path. At least one demonstrably clean path
gives `clean_path`, even if enumeration is incomplete. Otherwise
`conflicted_premises_only` requires complete own enumeration and every found path
tainted. All remaining cases, including no witness, give `not_fully_checked`.
Opposite checks used for quality do not create evidence for the conclusion or
spend its existence counters. Their uncertainty MUST remain visible in quality.

### K-EVAL-5 — Source state and availability

For a root with `source_requirement: current`, every named source MUST currently
resolve under policy. Failure disables that root and marks the channel incomplete
with `source_unavailable`; erasure never creates an opposing witness. `retained`
permits a retained, separately authorized immutable assessment after loss of source
bytes. `independent` is allowed only for an independently admitted attestation of
the exact target; it does not reconstruct the old bytes. `source_state` summarizes
found paths: prefer a fully resolvable path, then an independent attestation path,
then `prior_assessment_only`. This preference applies to complete sufficient
paths, not to the union of their roots. Order states from weakest to strongest
as prior_assessment_only, independent_attestation, resolvable_now. For one AND
path take the weakest state of every necessary premise path; for OR alternatives
choose the strongest state among complete witnessed paths. Thus one essential
retained-only premise prevents an AND path being labelled independently attested,
while a separate fully resolvable sufficient path may win. For a root, resolved
named sources (including the vacuous empty set) give resolvable_now; otherwise
an admitted independent attestation gives independent_attestation, and retained
assessment evidence gives prior_assessment_only. Certificate validity is already
required for an eligible rule; it does not upgrade its premises' source states.
If no witness, use authorized assessment or documentary
sources associated with the exact target: any unavailable/erased source yields
`prior_assessment_only`; otherwise `resolvable_now`. With no source at all the
latter is a vacuous resolution state, MUST NOT be rendered as a verified source.
An availability-only issue does not make a complete search incomplete unless a
current-required root could not be checked. Disclosed source references are exact
and sorted. Historical passing checks are never presented as fresh checks.

### K-EVAL-6 — Freshness

`usable_until` is the explicit query override if non-null; otherwise it is
confirmed_at plus the schema duration; otherwise null. If a duration applies and
confirmation is unknown, the item is stale and usable_until remains null. With
no duration or override freshness is `not_applicable`. With a horizon, `now <`
horizon is `fresh`, otherwise `stale`. Both polarities carry the item's freshness.
Staleness never alters validity, creates opposition, or removes a found witness.
A stale item can be the latest issuer statement; `currentness` identifies sequence
position, not freshness. Delivering a stale publication MUST be refused.

### K-EVAL-7 — Explanations and retrieval

`recall` performs exact selected-assertion evaluation, not top-k candidate retrieval;
search ranking is outside this profile. Its explanation is empty and complete
(no proofs requested). `explain` enumerates found proof paths, each the sorted set
of root-assessment and justification references used (rule certificates remain
pinned by the justification, not separate proof vertices), sorts/deduplicates those paths
by canonical JSON and takes the first `bounds.explanations`. Truncation gives
`partial` with `explanation_limit`, independently of evidence completeness. If
evaluation was incomplete, an untruncated explanation is partial with
`evaluation_limit`. Full and compact output MUST preserve the extended polarity
record unchanged. This profile has no lossy compact alternative.

### K-EVAL-8 — Dirty boundary and registered impact

Admitting a revision MUST atomically mark transitive registered sufficient-support
and review-on-change dependents dirty before a new-cut answer can be served.
`runtime.dirty` is a protected global inventory, never a public status. Each
unresolved cause is retained as `{assertion, revision}` in `runtime.dirty_causes`;
both exact refs must exist, the cause must be a revision, and each dirty assertion
must have at least one cause. A revision appends its cause to each affected
dependent atomically. Recalculation clears only the causes actually recomputed;
old resolved causes MUST NOT be inferred from all historical revisions later.

For a query, a dirty item is affected only if at least one retained cause has a
registered dependency/impact path to it eligible in that authorized projection.
Test the revision, changed target, path justifications, their necessary premises
and certificates with current read/use/metadata rights, disclosure, perspective,
context and valid_at before exposing any effect or charging logical work. Use the
registered edges immediately before that revision to identify its affected path;
a later withdrawal does not erase the invalidation reason. The revision must be
at or before the query cut. This protected traversal proves eligibility, not a
fresh evidence witness. An inaccessible branch or cause cannot qualify it.

Only such query-affected dirty items give both channels `not_found + incomplete`,
quality `not_fully_checked`, `needs_review: true` and cutoff `dirty`. A dirty item
with only hidden causes is evaluated normally over its unchanged authorized
graph; that does not clear global dirtiness or recompute the private projection.
Historical queries before the cause are unaffected. `review_required` contains
only authorized query-affected dirty assertions and assertions with eligible
review-on-change paths to historical/withdrawn inputs. A global dirty bit or
hidden review edge MUST NOT add a reference or alter any output field.

Querying a revised decision MUST still list eligible registered review dependents
even when their schemas differ. This draft's read evaluator does not clear dirty
state; a fully recalculated state may be supplied as a new complete snapshot.
It MUST NOT label an unvisited affected reverse-closure remainder clean. S24
keeps global dirtiness while the public projection remains equal and the
private-authorized control remains dirty/incomplete.

### K-EVAL-9 — Output order and currentness

Audience items are sorted by the protected internal reference before redaction.
Items, historical references, review references, source references, incompatibility
references and cutoffs MUST be deduplicated and sorted. `historical` lists visible
superseded versions in the requested selection's sequences, excluding explicit
historical targets already displayed. Overall currentness is `none` for no items,
`ambiguous_current` if any selected slot is ambiguous, `last_received` if any
unconfirmed imported publication is selected, and `current` otherwise; an explicit
historical item retains its own historical label. Source metadata and authority
receipts MUST obey the same visibility rules as content. `changes` uses the same
query and compares with an earlier captured projection. In fixtures, `since` is
the zero-based index of an earlier capture operation with matching principal,
purpose, audience, space, subject, schema and rule (otherwise `not_authorized`).
Null since means initial; otherwise changed iff visible content, qualification,
currentness or authorization projection changed. References list only currently
authorized changed items; a removal may give changed with an empty list. Hidden changes MUST NOT affect
that comparison. `since` is a protected saved-view binding, not a public global cursor.
For recall/explain the changes object is always initial with empty references.

### K-SNAP-1 — Frozen history and current applicability

A captured view is immutable history bound to its protected cut, source
frontiers, policy pins and selected item versions. Later knowledge or freshness
changes MUST NOT rewrite those bytes. Renderers MUST identify the item as being
at that snapshot's cut, never as an assertion about "now"; where numeric cuts
are protected, use its authorized snapshot handle and the historical label,
not a disclosed global counter. A current-state claim requires a new view.

The next delivery or external effect MUST apply current use/disclosure rights,
release decisions and erasure fences. It either refuses or uses a newly admitted
context; a cache, frozen snapshot or prompt-cache optimization grants no standing
permission. In these fixtures deliver refuses and never silently substitutes a
new context. The captured operation result remains unchanged after revocation.
Memory only reports changes; it does not restart, stop or re-prompt consumers,
and cannot recall bytes already delivered. P12 includes an allowed delivery
before revocation and a refused one afterwards with the same saved binding.

## Disclosure, handles and publication boundary

### K-DISC-1 — Lineage taint

Content lineage is distinct from logical premises. Effective audiences and purposes
are intersections of the proposed label, domain field defaults and all inputs;
retention ends at the earliest non-null deadline. Field classes are the union of
input and output field classes. Empty intersections admit a non-disclosable record,
not a public one. Every paraphrase, summary, excerpt, embedding, index, cache and
controlled export MUST retain content lineage. Read access does not authorize
retention or forwarding. No derivative may relabel away inherited constraints.

`lineage` is either an exact reference set or the literal `unknown`. A client's
citations are not a complete input inventory. The integration supplies protected
`policy.lineage_facts`, at most one per output, pinned to its integration profile:
`direct` lists no content inputs, `deterministic` lists the exact inputs read,
and `model` lists everything supplied to that call (context, tool results and
recalled views) within that profile's tracking boundary. `complete` asserts
completeness within that boundary, not knowledge of a model's prior training.
These are trusted intake facts in fixtures, never claims authenticated by an
output's own proposed lineage or logical premises.

Every proposal requires one integration fact; an absent fact is
`invalid_reference`. At intake, a complete fact's inputs replace the proposed
lineage. An incomplete fact yields `lineage: unknown`; its known input lower
bound is that fact's inputs, retained in the protected binding. In both cases all known inputs and
their transitive lineage constrain disclosure and erasure. Unknown lineage MUST
NOT contribute an item or evidence path to an audience_projection or delivery,
even with a public label or declassification assessment; this draft has no
default release of an unbounded derivation. Ordinary authorized private queries
may still inspect its qualified record under those inherited constraints.
Initial complete snapshots MUST retain the corresponding integration facts;
the fixture's facts for future proposals are protected admission evidence,
not already-admitted output records. Partial facts cannot be upgraded by copying their citations. No lineage fact grants read/use/retain rights.

For a write, resolve known inputs against the admitted pre-state plus every
proposal in that same atomic batch, independent of proposal array order. An
integration fact for a future output does not make that output present. Each
known input must resolve to an exact record in this hypothetical post-batch
state; otherwise return `invalid_reference` with no write. Initial admitted
records require all their known inputs in the initial snapshot, while protected
facts reserved for future proposals may refer to not-yet-admitted inputs.
Retention checks traverse the complete fact's inputs or an incomplete fact's
known lower bound, recursively through those resolved records' facts. Unknown
lineage never waives authority for a known input. Logical support edges alone
do not create content inputs, and no right is invented for unknown inputs.

### K-DISC-2 — Declassification

The caller needs declassify, admit and retain rights. `declassify.assessments`
contains a nonempty array of proposed owner assessments, followed atomically by
one new output assertion. Ordinary representation checks apply to each proposal
using relation `admit`; one caller does not impersonate several owners.
`disclosure.declassification` is the sorted set of those assessment references.
Each passing assessment MUST pin exact inputs, transformation id/version, output
schema, output body digest, audience and purpose, and exact policy/environment
pins. Its additional `decision` reference MUST match a trusted entry in
`policy.declassification_decisions`: exact owner and identical release pins.
Its issuer is that owner and executor is human or deterministic. A model's
semantic_review can propose a release but never supply this evidence.

`policy.constraint_owners` assigns the owners of each input's own constraints;
an absent entry means policy.owner. An entry's owners are nonempty and each exact
input appears at most once. Inherited constraints retain their original owners
through the transitive content-lineage closure. Every owner whose audience,
purpose or field-class restriction is lifted needs its own matching decision
and assessment; one owner's decision lifts only that owner's restriction.
Each assessment pins the same complete direct input set and output, even when
its owner's restriction originates deeper in that closure. The integration's
complete input set MUST equal the output lineage and every assessment's inputs.
Unknown lineage, missing owner evidence or mismatched pins yield
`declassification_invalid` atomically. Retention deadlines and erasure fences
are never widened by a release.

An assessment records evidence; it is not live authority. At admission and every
new disclosure, including queries and delivery, every cited decision MUST be active and absent
from `runtime.revoked_declassifications`. The `revoke_declassification` boundary
stimulus records an existing owner's revocation: only the exact decision owner
may apply it, otherwise `not_authorized`; it appends the exact decision ref and
returns a revoked receipt without changing any semantic record or cut. Retained
assessments remain history. If a decision no longer applies, ordinary inherited
constraints apply again: an inadmissible audience item is filtered, and delivery
of the prepared item yields `disclosure_revoked`.

This releases only the exact pinned structured output for that audience/purpose;
other inherited constraints remain. Field defaults may be widened only for that
output. The first publication path assembles structured audience fields; agent
free text enters only as a separately admitted semantic_inference proposal.
The audience may verify the released issuer statement, but MUST NOT see
hidden inputs, derivation, their ids, or hashes. An audience-projected item hides
internal ref, representation ref and authority receipt (null), source refs and
incompatibility refs (empty), and all internal witness-root ids (empty); the
count is the number of independently released witnesses, not hidden inputs.

### K-DISC-3 — Independent origins

A root origin is assigned at admitted source binding, not asserted by a copy to
increase independence. Reimports, mirrors and paraphrases of the same declaration
MUST share its origin for any independence count. A root assessment using multiple
sources still has its explicitly admitted origin; additional documentary copies
are attribution, not independent roots. New independent attestation requires a
separately reviewed root assessment and origin. Importer and original issuer
remain distinguishable in each source. Duplicate origins MUST NOT amplify evidence.

### K-DISC-4 — Subject handles

Every disclosed principal equal to the internal subject, including issuer,
submitter and perspective principal, MUST use the same audience handle. Other
principal identities require their own admitted public alias; absent aliases
yield `not_authorized` instead of exposing internal identity.
The closed `policy.handles` mapping is the alias source for EVERY disclosed
principal: look up the exact (internal principal as `subject`, record `space`,
query `audience`) tuple. This applies independently to subject, issuer,
submitter and perspective principal; a distinct representative MUST NOT be
rewritten as the issuer. Each mapping key has at most one handle. Handle values
must distinguish different internal principals within that space/audience.
Each (subject, space, audience) MUST have a policy-assigned opaque subject handle
for audience projection; absent mapping yields `not_authorized`. Handles across
spaces or audiences MUST NOT encode or share the internal subject id. Linking
handles is separately disclosed data under K-DISC-2. Every audience item uses
that mapped handle and excludes internal lineage. Protected publisher links may
retain internal ids but are never publication fields. Personal relationship,
contact, and introduction behavior belongs to the domain, never implied by a
shared subject or statement about relationship status.

### K-NI-1 — Semantic non-interference

Holding the authorized projection, policy, admitted logical envelope and explicitly
public availability constant, hidden appends, revisions, erasures, candidates and
work MUST NOT change visible status, count, ordering, root quality, coverage,
currentness, cursor behavior, success/refusal or completeness. Authorization
filtering precedes budget accounting. Hidden work cannot displace a visible root.
Admission/storage/work reservations MUST follow the actual disclosure boundary.
This is a semantic and metadata contract, not a constant-time or general
traffic-analysis guarantee.

### K-NI-2 — Handles and normalization

Every successful view request MUST mint an independent uniform 128-bit handle,
encoded as exactly 32 lowercase hex characters, regardless of visible or hidden
activity. All appearances inside that view use that handle. A write receipt uses
the same distribution, but an idempotent retry returns the identical prior receipt.
Protected bindings retain exact cuts and pagination state; no cut, global counter,
dirty generation or hidden-sensitive digest may be encoded in a handle or response.
Fixture symbolic handles are comparison slots, not wire values. Normalization may
replace only the listed fresh handle paths, preserving repeated-value equality,
required freshness across requests and fixed length/distribution. It MUST NOT
normalize success/refusal, semantic counts, timing classes, or policy revisions.
All supplied times are compared exactly; no fresh timestamp output is specified.
One run cannot prove a randomness distribution or timing isolation.

### K-NI-3 — Authorized availability

The only public degradation in this draft is `coarse_unavailable`, explicitly
admitted in policy before an event. Under degraded public availability a query
returns `unavailable`, never a not-found evidence result. With no such admission,
a failed resource envelope is a deployment nonconformance, not permission to
expose a new error. Harness `load` changes hidden_work only; it MUST NOT change
logical results. Harness `set_availability` is allowed only by the policy owner
under the predeclared coarse policy; other uses return `not_authorized`.

### K-PUB-1 — Four operations and the delivery check

Revision, revoke-onward-disclosure, unpublish and erase have distinct effects.
Memory computes a view; an external publisher assigns its own id/version and
stores a protected binding to it. The revoke operation appends a live revocation for its principal, audience,
purpose and right, authorized only by the policy owner; it changes no pinned
policy or historical receipt. A deliver request requires a prepared
`audience_projection` and rechecks current read, use and
forward rights, current policy, applicable owner release decisions, freshness and erasure fences using the prepared
view's exact selected items. Revocation gives `disclosure_revoked` even when the
old view was authorized. A stale, replaced or unconfirmed imported item gives
`publication_stale`. Success returns only a delivery receipt, not control rights.
No operation here deletes bytes at an independent recipient, unpublishes an
external artifact or sends content without an explicit delivery request.
Publications MUST contain no memory references, source cuts, handles or hidden
lineage; the publishing boundary retains only released fields and attribution.

### K-PUB-2 — Imported currentness

Publication-currentness rules apply only when an assertion has an authorized
associated source whose `source_kind` is `publication`, through an exact targeted
assessment/source association or documentary basis. The admission class alone
MUST NOT trigger them. A current issuer sequence reporting a mirror event may
remain `current`; this labels the report's sequence, never certifies the external
event or grants that mirror canonical authority. S23 contrasts such a mirror
with a genuine unchecked publication source. P07 supplies checked imports.

An imported publication retains its own source revision and original issuer.
A current import requires an admitted current-version check and an unexpired
horizon. Known replaced imports are historical and never current. Without a
current-version check the item is `last_received`, not claimed current. Root
support and provenance can still be displayed. Reimport neither refreshes issuer
confirmation time nor creates an independent origin. A receipt for delivery proves
delivery only, never which premise a recipient internally used.

## Operations, erasure and refusal

### K-API-1 — Atomic admission and idempotency

An operation MUST validate its entire batch against the hypothetical post-batch
state before committing anything. The idempotency identity is actor, space, key;
canonical request includes the complete authenticated intent except the key
itself and the intake stamp (`context.at`, or top-level `at` for erase), which
is not client intent. The complete retention_context is canonical intent for
admit, admit_raw, revise and declassify. An erase request includes its entire receipt_context in
canonical intent; changing that context under the same identity is a conflict.
Actor and admission class remain part of that intent. A currently authorized retry
with a later intake stamp MUST replay the original receipt and preserve the original
recorded time.
Same identity and identical canonical request MUST replay the exact receipt,
including handle, even if current head changed, subject to current authorization.
For an admission/revision/declassification replay, the original outputs and
their known content-input closure MUST still pass the exact retention context's
current authorization checks. Failure is `not_authorized` with no write, without
redacting, regenerating or overwriting the original receipt. A different retention
context is a different request; an otherwise authorized change under the same
identity is `idempotency_conflict`. A denied attempt creates no replay entry.
The deadline check uses the retry's current trusted `context.at`, not the
original recorded time. An exact retry at or after an original output/input
deadline MUST therefore refuse `not_authorized`, `retryable: false`, preserving
the original receipt and full state. A still-live exact retry returns that
unchanged receipt. Expiry also precedes a different-intent key conflict.
For an erase replay, every ref in the stored receipt must still satisfy the
receipt metadata test in K-ERASE-2; otherwise return `not_authorized` with no
write. Never redact, regenerate or overwrite the stored receipt to make a replay
authorized. Different request is
`idempotency_conflict`. Refused attempts commit no records, sequences, dirty flags
or idempotency entries. A successful batch commits records, lineage/custody
entries and dirty marking atomically. No received receipt means no assumed commit;
retry resolves uncertainty. For revise, admission sequence assignment orders the replacement (if any) before
the revision. Declassify orders the assessments in proposal-array order before its output. Other writes
that create no semantic record do not advance the record sequence.
Receipts MUST disclose only authorized record refs and
no writer sequence. Input arrays of proposals are transaction order, not sets.

### K-API-2 — Validation order and finite API

The semantic write API is admit, revise, declassify, erase and revoke; recall,
explain and changes are reads. `capture` is a harness read saved for later
comparison/delivery. `admit_raw` is the malformed-wire test variant of admit:
parse raw_json as an object containing only a proposals array, then use the
surrounding authenticated context, key and generation exactly as for admit. Restore, reconciliation, delivery and request_check exercise
boundary contracts; revoke_declassification records an external policy event;
load, set_availability and control are harness stimuli, not
kernel powers. Validation order is: JSON/shape/profile; policy and actor rights
(including exact retention grants, revocations and live deadlines for resolved
outputs and known inputs at the current trusted intake time);
idempotency replay/conflict; representation/review; erasure generation/fence;
reference/schema/content/time/context; authority/CAS; rule/cycle; resource limits.
Within one class use input order, then field-name order. The first violation
supplies the one typed refusal. Initial states are already admitted complete
snapshots; they MUST satisfy structural and referential invariants except explicit
runtime dirty, unavailable, erased and restore states. For reads, validate shape and public schema/rule lookup, policy pins, predeclared
availability, then the restore gate, before record filtering and evaluation. A
request_check always requests a new execution; existing assessments are obtained
by ordinary recall/explain instead. Unknown operation is
`unsupported_operation`; no arbitrary execution or check plug-in is permitted.

### K-API-3 — Resource bounds

Policy limits bound record count, per-rule fan-in, canonical proposal bytes and
per-read root/rule/source/explanation work. A write exceeding a limit yields
`limit_exceeded` atomically. Effective read bounds are the minimum of query and
admitted policy bounds, independently per component; zero is valid and visibly
incomplete only if eligible work exists. No unbounded-capacity or universal
performance promise is made. Source-resolution failure is an availability result,
not an unregistered negative premise. Cutoff reasons MUST be explicit and sorted.
This draft supplies no resumable evaluation cursor; a retry at the same protected
snapshot and larger bounds is the resumption mechanism.

### K-ERASE-1 — Custody closure and fence

Erase MUST first durably fence targets and their transitive content-lineage
closure, increment disposition generation, and close access and derivative commits.
Closure also traverses every custody entry's inputs, independently of logical
edges. Retained records may leave non-sensitive structural tombstones only;
payloads, excerpts and sensitive digests MUST become unrecoverable within the
named controlled boundary. `record_refs` in fixture postconditions includes
admitted tombstones; `erased_refs` identifies fenced erasure obligations; physical purge is established
only by custody dispositions and the erasure receipt, including after restore. Affected assertion payloads are omitted from query selection before counts;
per-record fences do not cause an existence-revealing query refusal. The separate
restore-wide fence refuses all reads. Source
headers may survive with effective availability erased; their erased bytes MUST
NOT appear in historical reads. Prior separately retained assessments without
content lineage to those bytes may survive with qualified source state.

### K-ERASE-2 — Erasure result and incomplete custody

Every controlled payload, summary, cache, index, export, backup and telemetry entry
in closure MUST have an accounted disposition. A requested boundary omitting a
controlled affected sink, or an unreachable affected sink, yields an `erase`
receipt with outcome `incomplete` and status `purge_pending`, while access stays
closed. Only reachable sinks named in the requested boundary are purged in that attempt.
Complete reachable closure yields `purged` and `purged_within_boundary`; a later
request with a different key may finish an incomplete purge.

Every erase request MUST supply `receipt_context: {audience, purpose}`. Its
recipient is exactly the authenticated `actor`; no other recipient can be named.
The current admitted policy and live revocations govern that exact context,
independently of any later query. Before applying the new fence or purge, filter
the full record closure through ordinary per-record K-AUTH-1 read/use/metadata
permission for actor, record space, receipt audience and receipt purpose, and the
record's applicable disclosure constraints. Never combine grants from different
audiences or purposes. Erase authority and policy ownership do not imply this
metadata permission. This test concerns approved structural refs only: existing
payload erasure or a fence does not itself revoke an otherwise authorized
structural identifier, and it never permits reconstruction of erased bytes.

Receipt `refs` is exactly the sorted metadata-authorized subset, possibly empty.
The protected closure, `erased_refs`, generation, fencing and custody accounting
MUST still cover every affected record, including omitted refs. Do not weaken
purge or turn it into a refusal merely because some refs are undisclosable.
The receipt's sorted `custody` lists only controlled affected sinks accounted for
in that attempt and named in the caller's requested boundary; independent
recipients never enter that list. Context changes are separate canonical intents;
exact replay requires the current authorization check in K-API-1.
Re-erasing a fenced target never reopens access.
Independent recipients are explicitly outside that promise and are never listed
as purged controlled sinks. No source-owner erasure is claimed without its receipt.
A receipt may preserve approved opaque ids and loss of replayability; it MUST NOT
promise both erased payloads and full reconstruction.

### K-ERASE-3 — Late writers and restore

Writes MUST carry the current `expected_generation`; an old generation gives
`stale_generation` even if the worker read before fencing. A current-generation
write derived from erased inputs gives `erasure_fenced`. Restore from an older
snapshot MUST keep disclosure fenced until an external witness outside the restored
failure domain reconciles all current obligations. For these closed fixtures, restore_cut MUST name the initial_state memory cut;
the initial snapshot is the supplied backup. Restore tentatively restores its
present custody payloads behind the fence, never its obsolete authority to read.
The admitted reference inventory and erasure obligations remain recorded; source
bytes are inaccessible even if restored storage is present. Restore records
`fenced`; an
unwitnessed reconciliation gives `erasure_incomplete`; reads while fenced give
`erasure_fenced`. A witnessed reconciliation reapplies fences and custody closure
before returning `reconciled`. An old snapshot's own erasure list is not that witness.
`external_witness: true` is a trusted adapter result establishing CURRENT COMPLETE
outside-domain verification of every current erasure and policy obligation at
reconciliation, not merely that an external, genuine or signed witness exists.
A stale external witness that covers only earlier obligations MUST be encoded
false; an incomplete obligation inventory MUST likewise never receive true.
The boolean abstracts verification, not its real deployment evidence. Fixtures
may trust this admitted fact; deployment reports must demonstrate its current
coverage and outside-domain origin. B10 pairs stale-witness refusal and continued
fencing with current-complete reconciliation.

### K-BOUND-1 — Data-only transport and control independence

Every memory response MUST be carried as data with item attribution and provenance.
Imperatives, signed text and summaries MUST NOT acquire instruction or control
status. A request for a new test or formal execution returns `execution_required`
as data and executes nothing. External stop, park and revocation control MUST
proceed under their existing owners even if memory is unavailable. The `control`
harness operation records that external observation and has no authority to make
it true. Deployment conformance requires observing the actual independent path.

### K-BOUND-2 — Deployment qualification

Documentary/embedded semantic conformance MUST NOT be reported as hostile-writer,
erasure, transport or isolation qualification. A protected deployment MUST prove
sole-writer custody, authenticated peer and current identity generation, server
identity, separately authorized source resolution and egress, durable fencing,
external-witness restore and independently reserved erasure/control capacity.
The exact numeric resource envelope, trusted identities, permitted source classes,
retention promises and availability disclosure are admitted deployment inputs.
Synthetic fixtures exercise the contract but do not certify those mechanisms.

### K-REF-1 — Closed refusal codes

A refusal contains only type, code and retryable. Codes and meanings are:

| Code | Meaning | Retryable |
| --- | --- | --- |
| invalid_json | Invalid encoding, duplicate keys or forbidden JSON numbers | false |
| invalid_shape | Unknown/missing field or structural variant | false |
| unknown_schema | Unknown exact domain version | false |
| unknown_profile | Unknown semantic profile | false |
| invalid_reference | Missing, malformed or inadmissible exact reference | false |
| duplicate_record | Reused id/version outside idempotent replay | false |
| invalid_domain_value | Content/type/cardinality/slot violation | false |
| invalid_time | Invalid timestamp, interval or cut | false |
| unknown_rule | Unknown projection rule/version | false |
| cycle | Sufficient graph or authority-order cycle | false |
| cross_scope | Unmapped cross-space reasoning input | false |
| representation_invalid | No checked authority to represent issuer | false |
| not_authorized | Missing operation/retention authority, expired output or known-input retention deadline, or invalid projection binding | false |
| quarantined | No affirmative admission review | false |
| authority_receipt_required | Missing qualifying canonical decision receipt, including a replacement/correction receipt that does not strictly succeed its target's receipt | false |
| version_conflict | Compare-and-set head mismatch | true |
| idempotency_conflict | Key reused for different canonical request | false |
| rule_unqualified | Sufficient rule lacks exact deterministic certificate | false |
| assessment_kind_invalid | Executor cannot mint the declared check kind | false |
| mode_mismatch | A proposed certificate/root improperly claims another context | false |
| limit_exceeded | Write exceeds admitted envelope | false |
| policy_mismatch | Query policy/evidence policy is not the named current policy | true |
| erasure_fenced | Input or read closed by a disposition fence | false |
| stale_generation | A writer uses an old disposition generation | true |
| erasure_incomplete | Restore obligations lack external completeness evidence | true |
| declassification_invalid | Missing or mismatched release pins | false |
| disclosure_revoked | Prepared delivery no longer authorized | false |
| publication_stale | Prepared item is stale, replaced or last-received only | true |
| unavailable | Predeclared coarse unavailability or unavailable memory boundary | true |
| execution_required | Requested evidence requires separate execution | false |
| unsupported_operation | Operation outside this finite API | false |

A boolean retryable describes whether changed state may permit a retry, not a
promise of automatic work. Query filtering MUST NOT leak which hidden record
would have caused a refusal. Physical failure without a receipt is not a typed
successful operation or a negative evidence result.

## Fixture execution

### K-VEC-1 — Complete snapshots and execution order

Each vector embeds all records, used domain documents, named projection rules,
authentication/policy facts and runtime state. Evaluate its ordered operations,
then its exact query. `expected.operation_results` is ordered one-to-one;
`expected.result` is the final query response; postconditions are exact admitted
reference inventory, erased payload inventory, present custody ids, dirty refs,
external-control observations and external effects. All inventories are sorted.
Refused operations leave those inventories unchanged. Fixtures are synthetic;
policy facts simulate admission, never prove a production security boundary.

### K-VEC-2 — Checkable forbidden predicates and pairs

Forbidden predicates are evaluated against the expected-shaped execution report
using JSON Pointer. `exists` tests path presence (including null), `equals` uses
typed JSON equality, `contains` tests array membership, `size_equals` tests array
length. A missing path is false for every predicate. Each forbidden predicate
MUST evaluate false. Normalization lists all handle paths and required equality
and distinctness groups. Equivalent-output pairs compare normalized objects after
replacing only declared handle slots with a fresh marker. Pair cases MUST retain
all status, count, budget, quality and availability fields; a permitted degraded
transition is asserted separately, never removed by normalization. These fixtures
make no timing proof and no statistical randomness certification.
