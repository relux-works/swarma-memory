"""Rebuild static draft schemas and synthetic domain documents using only stdlib."""
import copy
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = 'urn:bounded-evidence:0.2.6:'
S = {'type': 'string'}
I = {'type': 'integer'}
B = {'type': 'boolean'}
N = {'type': 'null'}
def enum(*v): return {'type': 'string', 'enum': list(v)}
def arr(v): return {'type': 'array', 'items': v}
def obj(**p): return {'type': 'object', 'properties': p, 'required': list(p), 'additionalProperties': False}
def choice(*v): return {'oneOf': list(v)}
def opt(v): return choice(v, N)
def ref(name): return {'$ref': BASE + name}
def const(v): return {'type': 'string', 'const': v}
R = obj(id=S, version=I)
VALUE = choice(S, I, B, arr(S))
PERSPECTIVE = obj(kind=enum('own', 'observer', 'team'), principal=S)
VALID = choice(obj(kind=const('known'), **{'from': S, 'to': opt(S), 'precision': const('second')}), obj(kind=const('unknown')))
DISCLOSURE = obj(audiences=arr(S), purposes=arr(S), retain_until=opt(S), field_classes=arr(enum('public', 'restricted', 'sensitive')), declassification=arr(R))
REP = obj(id=S, version=I, checked=B)
ENV = obj(id=S, version=I, kind=enum('assertion', 'source', 'justification', 'assessment', 'revision'), schema=opt(R), subject=S, issuer=S, submitter=S, representation_ref=opt(REP), perspective=PERSPECTIVE, admission_class=enum('self_declaration', 'imported_publication', 'machine_observation', 'semantic_inference'), space=S, valid=VALID, confirmed_at=opt(S), recorded=obj(sequence=I, at=S), lineage=choice(arr(R),const('unknown')), disclosure=DISCLOSURE, context=enum('real', 'simulated'))
LIT = obj(assertion=R, polarity=enum('support', 'oppose'))
PIN = obj(subject=R, rule=R, policy=R, environment=R)
DECLASS_PINS = dict(inputs=arr(R), transformation=R, output_schema=R, output_digest=S, audience=S, purpose=S)
DECLASS = obj(decision=R,**DECLASS_PINS)
BODIES = {
 'assertion': obj(statement_kind=enum('fact','self_declaration','proposal','decision_record','intent','assessment_summary'), slot=S, content=arr(obj(field=S,value=VALUE)), authority_receipt=opt(R)),
 'source': obj(owner=S, source_kind=enum('document','direct_declaration','publication','mirror','artifact'), object=S, revision=S, digest=opt(obj(algorithm=const('sha256-cjson-v1'), value=S)), provenance=enum('canonical','direct','imported','reported'), availability=enum('resolvable','unavailable','erased'), origin=S, original_issuer=S, carrier=opt(S), excerpt=opt(S), retention_admission=opt(R)),
 'justification': obj(target=LIT, premises=arr(choice(obj(kind=const('assertion'),literal=LIT),obj(kind=const('source'),source=R))), rule=R, rule_kind=enum('declared_rationale','checked_entailment'), role=enum('documentary_basis','review_on_change','sufficient_support'), check=opt(R)),
 'assessment': obj(check_kind=enum('source_binding','signature','test_result','formal_entailment','semantic_review','account_control','declassification'), executor=enum('human','deterministic','model'), result=enum('pass','fail','indeterminate'), pins=PIN, target=opt(LIT), sources=arr(R), origin=S, source_requirement=enum('current','retained','independent'), usable_until=opt(S), declassification=opt(DECLASS)),
 'revision': obj(relation=enum('replace','withdraw','correct','challenge','availability'), target=R, replacement=opt(R), availability=opt(enum('resolvable','unavailable','erased')), authority_receipt=opt(R))
}
SCHEMAS = {'envelope': ENV}
RECORDS=[]
PROPOSALS=[]
for name, body in BODIES.items():
    e = copy.deepcopy(ENV)
    e['properties']['kind'] = const(name)
    record = obj(envelope=e, body=body)
    SCHEMAS[name] = record
    RECORDS.append(ref(name))
    pe = copy.deepcopy(e)
    for k in ('submitter','recorded','admission_class'):
        del pe['properties'][k]
        pe['required'].remove(k)
    pe['properties']['representation_ref'] = opt(R)
    PROPOSALS.append(obj(envelope=pe,body=body))
RECORD = choice(*RECORDS)
PROPOSAL = choice(*PROPOSALS)
DOMAIN = obj(id=S,version=I,name=S,statement_kind=enum('fact','self_declaration','proposal','decision_record','intent','assessment_summary'), semantics=obj(establishes=S,does_not_establish=arr(S)), fields=arr(obj(name=S,type=enum('string','integer','boolean','string_set'),equality=enum('exact','set'),required=B,disclosure_class=enum('public','restricted','sensitive'))), cardinality=obj(mode=enum('single','multi'),slot_fields=arr(S)), incompatibilities=arr(obj(id=S,field=S,relation=const('unequal'),statement_kinds=arr(enum('fact','self_declaration','proposal','decision_record','intent','assessment_summary')), same=arr(enum('subject','space','perspective','slot')),overlap=const('required'))),freshness_default=choice(obj(kind=const('none')),obj(kind=const('duration'),seconds=I)),disclosure_defaults=arr(obj(field_class=enum('public','restricted','sensitive'),audiences=arr(S),purposes=arr(S))),requirements=arr(enum('authority_receipt_for_current','account_control_for_established','synthetic_only','no_derived_consent','adult_opt_in','mutual_contact_consent','mutual_partner_confirmation')))
SCHEMAS['domain-schema']=DOMAIN
RULE_BASE = dict(id=S,version=I,issuer=S,perspective=PERSPECTIVE,sequence_resolution=const('issuer_and_authority'),time_policy=const('query_cut'),freshness_policy=const('query_override_else_schema'),excluded_refs=arr(R))
SCHEMAS['projection-rule']=choice(*[obj(**RULE_BASE,family=const(f),audience=(S if f=='audience_projection' else N),purpose=(S if f=='audience_projection' else N)) for f in ('issuer_current','observer_model','audience_projection')])
BOUNDS=obj(roots=I,rules=I,source_resolutions=I,explanations=I)
CUT=obj(memory=I,sources=arr(obj(owner=S,revision=S)))
QUERY=obj(kind=enum('recall','explain','changes'),principal=S,purpose=S,audience=S,scope=obj(space=S,subject=S,schema=R,targets=arr(R)),projection_rule=R,evidence_policy=R,policy=R,cut=CUT,valid_at=S,now=S,mode=enum('real','simulated'),bounds=BOUNDS,usable_until=opt(S),render=enum('full','compact'),since=opt(I))
SCHEMAS['query']=QUERY
COVERAGE=choice(obj(kind=const('unknown')),obj(kind=const('declared'),ref=R))
POL=obj(witness=enum('present','not_found'),evaluation=enum('complete','incomplete'),corpus_coverage=COVERAGE,premise_quality=enum('clean_path','conflicted_premises_only','not_fully_checked'),evidence_qualification=arr(enum('semantic_review','test_result','formal_entailment','source_binding','signature','account_control','declassification')),source_state=enum('resolvable_now','prior_assessment_only','independent_attestation'),freshness=enum('fresh','stale','not_applicable'),authorized_snapshot_handle=S,dependency_coverage=const('registered_only'),witness_roots=arr(S),independent_root_count=I)
ITEM=obj(ref=opt(R),subject=S,issuer=S,submitter=S,perspective=PERSPECTIVE,representation_ref=opt(REP),admission_class=ENV['properties']['admission_class'],statement_kind=BODIES['assertion']['properties']['statement_kind'],content=BODIES['assertion']['properties']['content'],valid=VALID,confirmed_at=opt(S),usable_until=opt(S),currentness=enum('current','historical','ambiguous_current','last_received'),authority_receipt=opt(R),incompatible_with=arr(R),needs_review=B,source_refs=arr(R),support=POL,oppose=POL)
VIEW=obj(type=const('view'),semantic_profile=const('0.2.6-draft'),projection_rule=R,evidence_policy=R,policy=R,authorized_snapshot_handle=S,data_classification=const('data'),items=arr(ITEM),currentness=enum('none','current','ambiguous_current','last_received'),historical=arr(R),review_required=arr(R),explanation=obj(status=enum('complete','partial'),paths=arr(arr(R)),reason=opt(enum('explanation_limit','evaluation_limit'))),cutoffs=arr(enum('root_limit','rule_limit','source_limit','source_unavailable','dirty','runtime_unavailable')),changes=obj(state=enum('initial','changed','no_change'),refs=arr(R)))
SCHEMAS['view']=VIEW
CODES=['invalid_json','invalid_shape','unknown_schema','unknown_profile','invalid_reference','duplicate_record','invalid_domain_value','invalid_time','unknown_rule','cycle','cross_scope','representation_invalid','not_authorized','quarantined','authority_receipt_required','version_conflict','idempotency_conflict','rule_unqualified','assessment_kind_invalid','mode_mismatch','limit_exceeded','policy_mismatch','erasure_fenced','stale_generation','erasure_incomplete','declassification_invalid','disclosure_revoked','publication_stale','unavailable','execution_required','unsupported_operation']
REFUSAL=obj(type=const('refusal'),code=enum(*CODES),retryable=B)
SCHEMAS['refusal']=REFUSAL
RECEIPT=obj(type=const('receipt'),operation=enum('admit','revise','declassify','erase','revoke','revoke_declassification','restore','reconcile_restore','deliver','control','load','set_availability'),outcome=enum('admitted','revised','challenged','availability_changed','declassified','purged','incomplete','revoked','fenced','reconciled','delivered','proceeded'),receipt_handle=S,refs=arr(R),custody=arr(S),erasure_status=opt(enum('access_closed','purge_pending','purged_within_boundary','unavailable')))
SCHEMAS['receipt']=RECEIPT
RESPONSE=choice(ref('view'),ref('receipt'),ref('refusal'))
POLICY=obj(subject_principals=arr(obj(subject=S,principal=S)),revision=R,owner=S,lineage_facts=arr(obj(output=R,profile=R,kind=enum('direct','deterministic','model'),inputs=arr(R),complete=B)),constraint_owners=arr(obj(input=R,owners=arr(S))),declassification_decisions=arr(obj(ref=R,owner=S,pins=obj(**DECLASS_PINS),active=B)),profile=enum('documentary','protected','embedded'),grants=arr(obj(principal=S,space=S,audience=S,purpose=S,rights=arr(enum('read','use','retain','forward','admit','revise','erase','declassify')),records=arr(S),metadata=B)),representations=arr(obj(ref=R,issuer=S,submitter=S,space=S,relations=arr(enum('admit','replace','withdraw','correct','challenge','availability')),valid=B)),reviews=arr(obj(record=R,reviewer=S,result=enum('allow','quarantine'))),evidence=obj(ref=R,root_kinds=arr(enum('semantic_review','test_result','formal_entailment')),policy_pin=R,environment_pin=R),coverage=arr(obj(assertion=R,declaration=R)),authority_events=arr(obj(receipt=R,issuer=S,predecessors=arr(R),canonical=B)),handles=arr(obj(subject=S,space=S,audience=S,handle=S)),imports=arr(obj(source=R,status=enum('current','replaced','unverified'),successor=opt(R),checked_at=opt(S))),public_availability=enum('available','degraded'),availability_disclosure=enum('none','coarse_unavailable'),limits=obj(max_records=I,max_fan_in=I,max_payload_bytes=I,read=BOUNDS),source_access=arr(obj(source=R,resolvable=B)),external_effect_owners=arr(S))
RUNTIME=obj(dirty_causes=arr(obj(assertion=R,revision=R)),revoked_declassifications=arr(R),committed_cuts=arr(I),revocations=arr(obj(principal=S,audience=S,purpose=S,right=enum('read','retain','forward'),at=S,owner=S)),memory_cut=I,source_cuts=arr(obj(owner=S,revision=S)),dirty=arr(R),erasure_generation=I,erased=arr(R),fences=arr(R),custody=arr(obj(id=S,inputs=arr(R),kind=enum('payload','excerpt','summary','embedding','index','cache','export','backup','telemetry','independent_recipient'),controlled=B,reachable=B,present=B)),restore=obj(status=enum('open','fenced'),external_witness=B,obligations=arr(R)),idempotency=arr(obj(actor=S,space=S,key=S,canonical_request=S,receipt=ref('receipt'))),hidden_work=I,memory_available=B,control_observations=arr(enum('stop_proceeded','park_proceeded','revocation_proceeded')),external_effects=arr(S))
STATE=obj(records=arr(RECORD),domain_schemas=arr(ref('domain-schema')),projection_rules=arr(ref('projection-rule')),policy=POLICY,runtime=RUNTIME)
CTX=obj(actor=S,at=S,admission_class=ENV['properties']['admission_class'],retention_context=obj(audience=S,purpose=S))
OPS=[
 obj(op=const('admit_raw'),context=CTX,idempotency_key=S,raw_json=S,expected_generation=I),
 obj(op=const('admit'),context=CTX,idempotency_key=S,proposals=arr(PROPOSAL),expected_generation=I),
 obj(op=const('revise'),context=CTX,idempotency_key=S,revision=PROPOSAL,replacement=opt(PROPOSAL),expected_version=R,expected_generation=I),
 obj(op=const('declassify'),context=CTX,idempotency_key=S,assessments=arr(PROPOSAL),output=PROPOSAL,expected_generation=I),
 obj(op=const('erase'),actor=S,at=S,idempotency_key=S,targets=arr(R),boundary=arr(S),receipt_context=obj(audience=S,purpose=S)),
 obj(op=const('revoke'),actor=S,at=S,principal=S,audience=S,purpose=S,right=enum('read','retain','forward')),
 obj(op=const('revoke_declassification'),actor=S,at=S,decision=R),
 obj(op=const('capture'),query=ref('query')),
 obj(op=const('restore'),actor=S,at=S,restore_cut=I,external_witness=B,obligations=arr(R)),
 obj(op=const('reconcile_restore'),actor=S,at=S,external_witness=B,obligations=arr(R)),
 obj(op=const('deliver'),actor=S,at=S,view_operation=I,audience=S,purpose=S,publication=obj(id=S,version=I)),
 obj(op=const('request_check'),actor=S,at=S,evidence=R,check_kind=enum('test_result','formal_entailment')),
 obj(op=const('control'),actor=S,at=S,action=enum('stop','park','revocation')),
 obj(op=const('set_availability'),actor=S,at=S,state=enum('available','degraded')),
 obj(op=const('load'),actor=S,hidden_work=I)
]
# set_availability and load are test-harness stimuli, never writable kernel APIs.
POST=obj(record_refs=arr(R),erased_refs=arr(R),custody_present=arr(S),dirty=arr(R),control_observations=arr(S),external_effects=arr(S))
PRED=obj(path=S,test=enum('exists','equals','contains','size_equals'),value=choice(S,I,B,N,arr(S)))
NORMAL=obj(scheme=const('fresh_uniform_128_bit_hex'),fresh_handles=arr(S),equal_handles=arr(arr(S)),distinct_handles=arr(arr(S)),equivalent_outputs=arr(obj(left=S,right=S)),timestamps=const('exact'),timing_claim=const('none'))
SCHEMAS['vector']=obj(id=S,title=S,profile=enum('semantic','deployment'),clauses=arr(S),initial_state=STATE,operations=arr(choice(*OPS)),query=ref('query'),expected=obj(operation_results=arr(RESPONSE),result=RESPONSE,postconditions=POST),forbidden=arr(PRED),normalization=NORMAL)
SCHEMAS['fixture']=obj(name=S,initial_state=STATE,query=ref('query'))
for name, value in SCHEMAS.items():
    out={'$schema':'https://json-schema.org/draft/2020-12/schema','$id':BASE+name,**value}
    dest=ROOT/'kernel'/'schemas'/(name+'.schema.json')
    dest.parent.mkdir(parents=True,exist_ok=True)
    dest.write_text(json.dumps(out,indent=2,ensure_ascii=False)+'\n')

def domain(name,kind,mode,fields,slots=(),fresh=None,incompat=(),requirements=(),establishes='An attributed statement only.',limits=()):
    doc=dict(id='schema:'+name,version=1,name=name,statement_kind=kind,semantics=dict(establishes=establishes,does_not_establish=list(limits)),fields=[dict(name=n,type=t,equality='set' if t=='string_set' else 'exact',required=True,disclosure_class=c) for n,t,c in fields],cardinality=dict(mode=mode,slot_fields=list(slots)),incompatibilities=[dict(id='incompat:'+name+':'+f,field=f,relation='unequal',statement_kinds=[kind],same=['subject','space','perspective','slot'],overlap='required') for f in incompat],freshness_default=dict(kind='none') if fresh is None else dict(kind='duration',seconds=fresh),disclosure_defaults=[dict(field_class=c,audiences=['aud:public','aud:private'] if c=='public' else ['aud:private'],purposes=['purpose:read','purpose:publish']) for c in ['public','restricted','sensitive']],requirements=list(requirements))
    folder='decisions' if name in ['decision','rule','assumption','decision_proposal'] else 'profiles-synthetic'
    dest=ROOT/'domains'/folder/(name+'.json'); dest.parent.mkdir(parents=True,exist_ok=True)
    dest.write_text(json.dumps(doc,indent=2)+'\n')
    return doc

domain('decision','decision_record','single',[('value','string','public')],requirements=['authority_receipt_for_current'],establishes='An assertion about an exact deciding-authority receipt.',limits=['Permission to act','Adoption without a canonical receipt'])
domain('rule','fact','single',[('value','string','public')],incompat=['value'],limits=['Automatic execution'])
domain('assumption','fact','multi',[('value','string','public')],limits=['Unregistered dependencies','Truth from documentary attribution'])
domain('decision_proposal','proposal','multi',[('value','string','public')],limits=['Adopted status'])
common=['synthetic_only']
domain('interest','self_declaration','multi',[('value','string','public')],requirements=common,limits=['A verified skill'])
domain('interest_hypothesis','proposal','multi',[('value','string','restricted')],requirements=common,limits=['The subject made this statement'])
domain('competence','self_declaration','multi',[('skill','string','public'),('level','string','public')],requirements=common,limits=['Established competence without separately scoped evidence'])
domain('location','self_declaration','single',[('kind','string','public'),('value','string','sensitive')],slots=['kind'],fresh=604800,incompat=['value'],requirements=common,limits=['Public disclosure of exact location'])
domain('location_city','self_declaration','single',[('value','string','public')],fresh=604800,requirements=common,limits=['Disclosure of hidden coordinates or derivation'])
domain('availability','self_declaration','single',[('value','string','restricted')],fresh=86400,incompat=['value'],requirements=common)
domain('intent','intent','multi',[('value','string','restricted')],fresh=604800,requirements=common,limits=['A commitment','Consent to contact'])
domain('account_link','self_declaration','multi',[('account','string','restricted')],requirements=common+['account_control_for_established'],limits=['Proven account control without an exact account_control assessment'])
domain('relationship_status','self_declaration','single',[('value','string','sensitive')],incompat=['value'],requirements=common+['no_derived_consent','mutual_partner_confirmation'],limits=['Consent to introductions','Consent to publish a partner link'])
domain('open_to_introductions','self_declaration','single',[('enabled','boolean','sensitive'),('adult_opt_in','boolean','sensitive')],requirements=common+['no_derived_consent','adult_opt_in','mutual_contact_consent'],limits=['Contact details may be disclosed','Consent inferred from relationship status'])
print(f'Wrote {len(SCHEMAS)} schemas and 14 domain documents.')
