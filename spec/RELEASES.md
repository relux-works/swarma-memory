# Package releases

## 0.3.0-draft

K-SRC-1 adds the required, citation-closed source table with live and erased
variants, shared effective availability, byte-exact retained excerpts, source-aware
changes and frozen captures. Audience projections omit sources. S43–S53 cover
presentation, non-interference and write refusals. The source digest enum adds
`sha256-bytes-v1`. All package URNs and semantic profiles now consistently use
0.3.0, resolving the prior 0.2.6 schema / 0.2.7 package label mismatch.

## 0.2.7-draft

The Swarma adapter binds kernel principals (issuer, subject, submitter) to platform identity cells resolved through the owner registry; the representation basis is a registry grant checked at admission; an unavailable registry is never a grant. Key rotation and revocation are stated for the adapter. Kernel semantics, schemas and all 74 vectors are unchanged.

## 0.2.6-draft

Issuer-local authority order (clause K-REV-3): the order of an issuer's decisions is reachability over predecessor edges between that issuer's own events only. One all-issuer path suffices; foreign events are never contracted into a bypass edge; foreign branches cannot cancel an all-issuer path; mixed graphs stay admissible; a missing path leaves the candidates `ambiguous_current`. Currentness and strict replacement succession share the relation. Vectors S34–S42 added.

## 0.2.1-draft – 0.2.5-draft

Corrections found by two independent evaluators and adversarial cases: authority receipt scope and succession, retention context and deadline gates, multi-owner declassification, the restore witness (current complete outside-domain verification of every current obligation), restore with current erasure obligations, premise-quality aggregation, and several fixture and checker fixes. No release changed the five-record model.

## 0.2.0-draft

Kernel brought to the consolidated contract: snapshot applicability, lineage completeness, declassification as evidence of a decision rather than an authority, three distinct conflict outcomes, owner-selected projection exclusion, the normalized input tuple for portability. Vectors P12–P15 added.

## 0.1.0-draft

First closed package: normative kernel text, closed JSON schemas, the decisions and synthetic profiles domain packages, the Swarma adapter contract, and the structural checker.
