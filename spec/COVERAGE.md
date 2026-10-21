# Coverage

Every conformance vector and the normative clauses of `kernel/semantics.md` it exercises. All 53 normative clauses are exercised by at least one vector. A listed clause does not claim exhaustive testing of every sentence of that clause.

| Vector id | Profile | Normative clauses in kernel/semantics.md | What it checks |
| --- | --- | --- | --- |
| S01 | semantic | K-SCOPE-1, K-EVAL-1, K-EVAL-3, K-VEC-1, K-TIME-1 | No roots do not create opposition |
| S02 | semantic | K-EVAL-1, K-REC-2, K-REC-3 | Both independent signs remain visible |
| S03 | semantic | K-EVAL-4, K-RULE-1, K-RULE-2 | Conflicted premises support only the explicit conclusion |
| S04 | semantic | K-REV-2, K-EVAL-1, K-RULE-2 | Withdrawing one root preserves the alternative |
| S05 | semantic | K-REV-2, K-EVAL-1 | Withdrawal of sole required support is not refutation |
| S06 | semantic | K-EVAL-2, K-API-3, K-NI-2 | A bounded walk cannot conclude complete absence |
| S07 | semantic | K-EVAL-7, K-EVAL-2 | Proof rendering limit does not limit evidence evaluation |
| S08 | semantic | K-RULE-1, K-API-1, K-REF-1 | Atomic cycle rejection |
| S09 | semantic | K-TIME-1, K-REV-2 | Backdated validity does not backdate knowledge |
| S10 | semantic | K-TIME-1, K-DOM-2, K-DOM-3 | Half-open validity and explicit cross-assertion incompatibility |
| S11 | semantic | K-REC-2, K-REC-3 | Exact assessment pins cannot be copied to another candidate |
| S12 | semantic | K-EVAL-5, K-ERASE-1, K-TIME-1 | Erased current-required source yields an explicit gap |
| S13 | semantic | K-AUTH-1, K-NI-1, K-NI-2, K-VEC-2 | Hidden opposing evidence is excluded before evaluation |
| S14 | semantic | K-JSON-1, K-JSON-2, K-API-1 | Idempotency is exact canonical request identity |
| S15 | semantic | K-REC-2, K-PROJ-1 | Simulation evidence does not establish a real result |
| S16 | semantic | K-RULE-2, K-ENV-3, K-REC-2 | A proposed checked rule needs a deterministic certificate |
| S17 | semantic | K-EVAL-8, K-API-1, K-REV-1 | Input revision makes dependent unavailable as fresh until recomputed |
| S18 | semantic | K-JSON-1, K-API-2, K-REF-1 | Unknown input field is refused without interpretation |
| S19 | semantic | K-REV-1, K-REV-3, K-SCOPE-1 | External decisions survive attributed memory challenges |
| S20 | semantic | K-DISC-1, K-ERASE-1, K-ERASE-2 | Erasure traverses a derivative with no justification edge |
| S21 | semantic | K-RULE-1, K-RULE-2, K-EVAL-1 | Opposing premises do not contrapose into an opposing conclusion |
| S22 | semantic | K-REC-1, K-REC-3, K-RULE-2 | Documentary and signature evidence is not semantic support |
| S23 | semantic | K-REC-1, K-REV-3, K-PROJ-1, K-PUB-2 | Mirror report currentness is separate from genuine publication currentness |
| S24 | semantic | K-NI-1, K-NI-2, K-VEC-2, K-EVAL-8, K-AUTH-1 | Hidden dependency invalidation cannot dirty an unchanged public projection |
| S25 | semantic | K-ERASE-3, K-ERASE-2 | Restore stays fenced without an outside completeness witness |
| S26 | semantic | K-ERASE-3, K-DISC-1 | Late derivative commit rejects the stale disposition generation |
| S27 | semantic | K-NI-1, K-NI-2, K-NI-3, K-API-3, K-VEC-2 | Hidden work preserves results and explicit degradation remains visible |
| S28 | semantic | K-REV-3, K-EVAL-9 | Unordered authority replacements remain ambiguous |
| S29 | semantic | K-REV-3, K-TIME-1, K-EVAL-9 | Authority predecessor order overrides late admission order |
| S30 | semantic | K-EVAL-3, K-REC-1, K-DISC-3 | Complete registered evaluation leaves source corpus coverage unknown |
| S31 | semantic | K-EVAL-4, K-EVAL-7 | Compact rendering preserves conflicted-premise quality |
| S32 | semantic | K-EVAL-5, K-REC-2, K-ERASE-1 | Retained checks and complete AND versus OR paths preserve source states |
| S33 | semantic | K-DOM-1, K-JSON-1 | Unknown exact domain version is refused |
| S34 | semantic | K-REV-3, K-REV-4, K-EVAL-9 | A foreign intermediate cannot be contracted into H1 authority order |
| S35 | semantic | K-REV-3, K-EVAL-9 | An assertion-free H1 event establishes transitive H1 order |
| S36 | semantic | K-REV-3, K-EVAL-9 | One direct H1 path suffices despite a parallel mixed path |
| S37 | semantic | K-REV-3, K-VEC-2, K-EVAL-9 | Foreign-only edge removal preserves unordered H1 candidates |
| S38 | semantic | K-REV-3, K-VEC-2, K-EVAL-9 | Foreign-only edge removal preserves an established H1 order |
| S39 | semantic | K-REV-1, K-REV-3, K-REV-4, K-REF-1, K-API-1, K-EVAL-8 | Mixed-only succession refuses replace and correct but permits canonical import |
| S40 | semantic | K-REV-1, K-REV-3, K-REF-1, K-API-1, K-EVAL-8 | Replacement accepts an all-H1 path through an assertion-free event |
| S41 | semantic | K-REV-1, K-REV-3, K-REF-1, K-API-1, K-EVAL-8 | Correction accepts one direct H1 path beside a mixed branch |
| S42 | semantic | K-REV-3, K-ENV-1, K-EVAL-9 | Carrier and submitter changes do not change protected H1 event order |
| P01 | semantic | K-ENV-1, K-ENV-3, K-PROJ-1, K-SCOPE-1 | Observer hypothesis does not become a subject self-description |
| P02 | semantic | K-ENV-2, K-REV-1, K-ENV-1, K-ENV-3 | Representation and subject identity cannot be invented for self-declarations |
| P03 | semantic | K-REV-1, K-ENV-1, K-PROJ-1 | Later observer evidence cannot replace the issuer sequence |
| P04 | semantic | K-EVAL-6, K-DOM-1, K-TIME-1 | Expired seven-day location horizon stays a stale statement |
| P05 | semantic | K-DISC-1, K-DISC-2, K-DISC-4, K-JSON-2, K-PUB-1 | Every constrained owner must currently release the exact city |
| P06 | semantic | K-PUB-1, K-AUTH-1 | Revocation between preparation and delivery blocks the send |
| P07 | semantic | K-DISC-3, K-PUB-2, K-EVAL-3 | Three attributed imports retain one witness root |
| P08 | semantic | K-ERASE-1, K-ERASE-2, K-DISC-1, K-API-1, K-AUTH-1 | Complete erasure does not grant hidden receipt metadata |
| P09 | semantic | K-DISC-4, K-DISC-2, K-NI-1 | Public subject handles and issuer attribution do not reveal private linkage |
| P10 | semantic | K-REV-1, K-ENV-2, K-API-1, K-TIME-1 | Concurrent representatives receive one commit and one version conflict |
| P11 | semantic | K-DISC-1, K-AUTH-1, K-ENV-3, K-API-1, K-API-2, K-REF-1, K-TIME-1 | Exact scope and live deadlines govern retention and replay |
| P12 | semantic | K-SNAP-1, K-PUB-1, K-AUTH-1, K-SCOPE-1 | Frozen snapshot stays historical after current disclosure is revoked |
| P13 | semantic | K-DISC-1, K-ENV-3, K-PROJ-1, K-NI-1, K-AUTH-1, K-API-1 | Known lineage bounds retention across an atomic batch and empty labels |
| P14 | semantic | K-REV-4, K-REV-1, K-API-1 | Write version conflict is neither ambiguous currentness nor evidence conflict |
| P15 | semantic | K-PROJ-2, K-PROJ-1, K-REV-2, K-DISC-4 | Audience exclusion does not revise the organisation record |
| B01 | semantic | K-REV-1, K-REV-3, K-REF-1, K-API-1, K-EVAL-8, K-EVAL-9 | Only strict authority successors replace; replay and CAS stay distinct |
| B02 | semantic | K-REV-3, K-REC-1, K-ENV-3 | Unreceipted decision text can enter only as an explicit proposal |
| B03 | semantic | K-REC-1, K-REV-3, K-BOUND-1 | A remote activity mirror proves only the attributed report |
| B04 | deployment | K-BOUND-1, K-PUB-1, K-REC-3 | Signed imperative remains data through an authorized delivery |
| B05 | deployment | K-AUTH-1, K-PUB-1, K-BOUND-2 | A prior purpose-bound view cannot authorize another purpose |
| B06 | deployment | K-AUTH-1, K-NI-1, K-EVAL-9, K-BOUND-2 | Revoked read access yields no identifiers paths or counts |
| B07 | semantic | K-NI-1, K-NI-2 | Hidden append revise and erase preserve the public projection |
| B08 | semantic | K-AUTH-1, K-EVAL-2, K-NI-1, K-API-3 | Hidden candidates cannot spend a visible query budget |
| B09 | deployment | K-NI-3, K-BOUND-2, K-VEC-2 | Shared exhaustion exposes only a preauthorized coarse transition |
| B10 | deployment | K-ERASE-1, K-ERASE-2, K-ERASE-3, K-BOUND-2 | An external restore witness reapplies erasure before reopening reads |
| B11 | deployment | K-ERASE-3, K-BOUND-2 | A physically delayed derivative writer cannot cross an erasure fence |
| B12 | semantic | K-API-1, K-JSON-2 | Duplicate import replays one receipt and changed intent conflicts |
| B13 | semantic | K-EVAL-5, K-EVAL-3 | Unavailable source leaves an incomplete knowledge result |
| B14 | semantic | K-EVAL-1, K-EVAL-2, K-API-3 | A surviving sufficient alternative preserves support |
| B15 | semantic | K-EVAL-1, K-EVAL-2, K-API-3 | A dependency cap cannot masquerade as complete absence |
| B16 | deployment | K-BOUND-1, K-BOUND-2 | External stop park and revocation proceed while memory is unavailable |
| B17 | deployment | K-BOUND-1, K-REC-3, K-API-2 | Requesting a fresh test launches no execution |

| S43 | semantic | K-SRC-1, K-EVAL-5, K-DISC-3 | Two assertions share one byte-exact retained source without a witness |
| S44 | semantic | K-SRC-1, K-EVAL-5, K-EVAL-9, K-SNAP-1 | An unavailable revision preserves the excerpt and changes the citing item |
| S45 | semantic | K-SRC-1, K-ERASE-1, K-SNAP-1 | Erasure redacts current and historical source bytes while an earlier capture stays full |
| S46 | semantic | K-SRC-1, K-NI-1, K-AUTH-1, K-EVAL-9, K-VEC-2 | Hidden source append revision and erasure preserve public changes with private controls |
| S47 | semantic | K-SRC-1, K-NI-1, K-AUTH-1, K-VEC-2 | A visible source cited only through a hidden justification stays absent |
| S48 | semantic | K-SRC-1, K-NI-1, K-AUTH-1, K-VEC-2 | A query targeting a hidden source matches a nonexistent id |
| S49 | semantic | K-SRC-1, K-DISC-2, K-AUTH-1 | Audience projection omits public source payloads and references |
| S50 | semantic | K-SRC-1, K-EVAL-2, K-EVAL-5 | Source payload construction spends no source-resolution budget |
| S51 | semantic | K-SRC-1, K-REF-1, K-JSON-1, K-API-1 | Excerpt retention and digest algorithm refusals precede a valid source control |
| S52 | semantic | K-SRC-1, K-ERASE-1 | A fence alone redacts source bytes at current and historical cuts |
| S53 | semantic | K-SRC-1, K-EVAL-5, K-REC-3 | A retained excerpt cannot satisfy a current-required root |
