#!/usr/bin/env python3
"""Structural/consistency checks only; this is deliberately not an evidence evaluator."""
import copy
import json
import re
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
BASE='urn:bounded-evidence:0.2.6:'
ERRORS=[]
class Invalid(ValueError): pass

def strict_equal(a,b):
    if type(a) is not type(b): return False
    if isinstance(a,dict): return a.keys()==b.keys() and all(strict_equal(a[k],b[k]) for k in a)
    if isinstance(a,list): return len(a)==len(b) and all(strict_equal(x,y) for x,y in zip(a,b))
    return a==b

def pairs(items):
    result={}
    for k,v in items:
        if k in result: raise Invalid(f'duplicate JSON key {k!r}')
        result[k]=v
    return result

def no_float(x): raise Invalid(f'forbidden JSON number {x!r}')
def integer(x):
    n=int(x)
    if not -(2**53-1)<=n<=2**53-1: raise Invalid('integer outside exact range')
    return n

def parse(text):
    value=json.loads(text,object_pairs_hook=pairs,parse_float=no_float,parse_int=integer,parse_constant=no_float)
    def scan(x):
        if isinstance(x,str) and any(0xD800<=ord(c)<=0xDFFF for c in x): raise Invalid('unpaired surrogate')
        if isinstance(x,dict):
            for k,v in x.items(): scan(k);scan(v)
        elif isinstance(x,list):
            for v in x: scan(v)
    scan(value)
    return value

MISSING=object()
def pointer(value,path,missing=MISSING):
    if path=='': return value
    if not path.startswith('/'): raise Invalid('not a JSON Pointer: '+path)
    for part in path[1:].split('/'):
        part=part.replace('~1','/').replace('~0','~')
        if isinstance(value,dict) and part in value: value=value[part]
        elif isinstance(value,list) and part.isdecimal() and int(part)<len(value): value=value[int(part)]
        else: return missing
    return value

def set_pointer(value,path,replacement):
    parent,part=path.rsplit('/',1);container=pointer(value,parent)
    if container is MISSING: raise Invalid('missing normalized path '+path)
    if isinstance(container,list): container[int(part)]=replacement
    else: container[part.replace('~1','/').replace('~0','~')]=replacement

class Validator:
    """The exact JSON Schema subset used by this package, without remote resolution."""
    supported={'$schema','$id','$ref','type','required','properties','additionalProperties','enum','const','items','oneOf'}
    def __init__(self,schemas): self.schemas=schemas
    def resolve(self,reference):
        uri,_,fragment=reference.partition('#')
        if uri not in self.schemas: raise Invalid('unknown package schema reference '+uri)
        result=self.schemas[uri]
        if fragment:
            result=pointer(result,fragment)
            if result is MISSING: raise Invalid('unresolved package fragment '+reference)
        return result
    def check(self,value,schema,path='$'):
        if '$ref' in schema: self.check(value,self.resolve(schema['$ref']),path)
        typ=schema.get('type')
        checks={'object':lambda x:type(x) is dict,'array':lambda x:type(x) is list,'string':lambda x:type(x) is str,'integer':lambda x:type(x) is int,'boolean':lambda x:type(x) is bool,'null':lambda x:x is None}
        if typ and (typ not in checks or not checks[typ](value)): raise Invalid(f'{path}: expected {typ}')
        if 'const' in schema and not strict_equal(value,schema['const']): raise Invalid(f'{path}: const mismatch')
        if 'enum' in schema and not any(strict_equal(value,x) for x in schema['enum']): raise Invalid(f'{path}: enum mismatch')
        if isinstance(value,dict):
            missing=set(schema.get('required',[]))-value.keys()
            if missing: raise Invalid(f'{path}: missing {sorted(missing)}')
            properties=schema.get('properties',{})
            extra=value.keys()-properties.keys()
            if schema.get('additionalProperties') is False and extra: raise Invalid(f'{path}: unknown fields {sorted(extra)}')
            for k,subschema in properties.items():
                if k in value:self.check(value[k],subschema,path+'/'+k)
        if isinstance(value,list) and 'items' in schema:
            for i,v in enumerate(value):self.check(v,schema['items'],f'{path}/{i}')
        if 'oneOf' in schema:
            successes=0; failures=[]
            for branch in schema['oneOf']:
                try:self.check(value,branch,path);successes+=1
                except Invalid as e:failures.append(str(e))
            if successes!=1:raise Invalid(f'{path}: oneOf matched {successes}; '+ '; '.join(failures[:3]))
    def closed(self,schema,path='$'):
        if not isinstance(schema,dict):raise Invalid(path+': schema must be an object')
        unknown=set(schema)-self.supported
        if unknown:raise Invalid(path+': unsupported schema keywords '+repr(sorted(unknown)))
        if schema.get('type')=='object' or 'properties' in schema:
            if schema.get('additionalProperties') is not False:raise Invalid(path+': object is not closed')
            if schema.get('type')!='object':raise Invalid(path+': object lacks explicit type')
            if set(schema.get('required',[]))-set(schema.get('properties',{})):raise Invalid(path+': undefined required field')
        if '$ref' in schema:self.resolve(schema['$ref'])
        for name,child in schema.get('properties',{}).items():self.closed(child,path+'/'+name)
        if 'items' in schema:self.closed(schema['items'],path+'/items')
        for i,child in enumerate(schema.get('oneOf',[])):self.closed(child,f'{path}/oneOf/{i}')

def require(condition,message):
    if not condition:raise Invalid(message)
def rkey(r):return (r['id'],r['version'])
def ref_of(record):return (record['envelope']['id'],record['envelope']['version'])
def schema_ref(doc):return (doc['id'],doc['version'])

def check_domain(d):
    names=[x['name'] for x in d['fields']]
    require(len(names)==len(set(names)),'duplicate domain fields')
    require(bool(names),'domain has no fields')
    for field in d['fields']:
        require(field['equality']==('set' if field['type']=='string_set' else 'exact'),'field equality disagrees with its type')
    require(set(d['cardinality']['slot_fields'])<=set(names),'unknown slot field')
    if d['cardinality']['mode']=='multi':require(not d['cardinality']['slot_fields'],'multi schema has slot fields')
    for rule in d['incompatibilities']:
        require(rule['field'] in names,'unknown incompatibility field')
        require(set(rule['same'])=={'subject','space','perspective','slot'},'incomplete incompatibility scope')
        require(d['statement_kind'] in rule['statement_kinds'],'incompatibility excludes own schema kind')
    if d['statement_kind']=='proposal':require(not d['incompatibilities'],'proposal schema deterministically opposes another proposal')
    if d['freshness_default']['kind']=='duration':require(d['freshness_default']['seconds']>0,'nonpositive freshness duration')
    require({x['field_class'] for x in d['disclosure_defaults']}=={'public','restricted','sensitive'},'missing disclosure default')

def check_state(s,documents):
    records=s['records'];keys=[ref_of(x) for x in records];known=set(keys)
    require(len(keys)==len(known),'duplicate initial record reference')
    sequences=[x['envelope']['recorded']['sequence'] for x in records]
    require(len(sequences)==len(set(sequences)),'duplicate admission sequence')
    require(all(0<x<=s['runtime']['memory_cut'] for x in sequences),'record beyond initial cut')
    cuts=s['runtime']['committed_cuts']
    require(cuts==sorted(set(cuts)) and s['runtime']['memory_cut'] in cuts and all(0<=c<=s['runtime']['memory_cut'] for c in cuts),'invalid committed transaction boundaries')
    ds={schema_ref(d):d for d in s['domain_schemas']}
    require(len(ds)==len(s['domain_schemas']),'duplicate embedded domain')
    for k,d in ds.items():require(k in documents and strict_equal(d,documents[k]),'embedded domain differs from canonical document '+str(k))
    def exists(r,label):require(rkey(r) in known,'dangling '+label+' '+str(rkey(r)))
    identities={(x['subject'],x['principal']) for x in s['policy']['subject_principals']}
    require(len(identities)==len(s['policy']['subject_principals']),'duplicate subject identity binding')
    facts=s['policy']['lineage_facts']
    fact_by_output={rkey(f['output']):f for f in facts}
    require(len(fact_by_output)==len(facts),'duplicate integration lineage fact')
    for f in facts:
        require(len(f['inputs'])==len({rkey(r) for r in f['inputs']}),'duplicate integration input')
        if f['kind']=='direct':require(not f['inputs'] and f['complete'],'direct lineage is not complete and empty')
        # Future-proposal evidence is not an admitted record; its inputs are checked at intake.
        if rkey(f['output']) in known:
            for r in f['inputs']:exists(r,'integration input')
    owners=s['policy']['constraint_owners']
    require(len(owners)==len({rkey(o['input']) for o in owners}),'duplicate constraint owner binding')
    for o in owners:
        exists(o['input'],'constraint owner input')
        require(bool(o['owners']) and len(o['owners'])==len(set(o['owners'])),'empty or duplicate constraint owners')
    decisions=s['policy']['declassification_decisions']
    require(len(decisions)==len({rkey(d['ref']) for d in decisions}),'duplicate release decision')
    for d in decisions:
        for r in d['pins']['inputs']:exists(r,'release decision input')
    for r in s['runtime']['revoked_declassifications']:
        require(rkey(r) in {rkey(d['ref']) for d in decisions},'unknown revoked release decision')
    dirty={rkey(r) for r in s['runtime']['dirty']}
    causes=s['runtime']['dirty_causes']
    require({rkey(c['assertion']) for c in causes}==dirty,'dirty inventory lacks exact unresolved causes')
    require(len(causes)==len({(rkey(c['assertion']),rkey(c['revision'])) for c in causes}),'duplicate dirty cause')
    record_by_ref={ref_of(r):r for r in records}
    for c in causes:
        exists(c['assertion'],'dirty assertion');exists(c['revision'],'dirty revision')
        require(record_by_ref[rkey(c['assertion'])]['envelope']['kind']=='assertion','dirty target is not assertion')
        require(record_by_ref[rkey(c['revision'])]['envelope']['kind']=='revision','dirty cause is not revision')
    mappings=s['policy']['handles']
    require(len(mappings)==len({(h['subject'],h['space'],h['audience']) for h in mappings}),'duplicate public alias key')
    require(len(mappings)==len({(h['handle'],h['space'],h['audience']) for h in mappings}),'public aliases merge principals')
    for rule in s['projection_rules']:
        if rule['family']!='audience_projection':require(not rule['excluded_refs'],'exclusion outside audience projection')
    for rec in records:
        e=rec['envelope'];b=rec['body']
        require(ref_of(rec) in fact_by_output,'missing integration lineage fact')
        f=fact_by_output[ref_of(rec)]
        require(e['lineage']==(f['inputs'] if f['complete'] else 'unknown'),'lineage differs from integration fact')
        for r in (e['lineage'] if isinstance(e['lineage'],list) else []):exists(r,'lineage')
        if e['issuer']==e['submitter']:require(e['representation_ref'] is None,'unneeded representation reference')
        else:require(e['representation_ref'] is not None and e['representation_ref']['checked'],'missing checked representation')
        if e['kind']=='assertion':
            require(rkey(e['schema']) in ds,'unknown initial assertion schema')
            d=ds[rkey(e['schema'])];require(b['statement_kind']==d['statement_kind'],'assertion statement kind disagrees with schema')
            if b['statement_kind']=='self_declaration' or e['admission_class']=='self_declaration':
                require((e['subject'],e['issuer']) in identities and e['perspective']==dict(kind='own',principal=e['issuer']),'self-declaration lacks subject issuer identity')
            fields={x['field']:x['value'] for x in b['content']};declared={x['name']:x for x in d['fields']}
            require(len(fields)==len(b['content']),'duplicate assertion content field')
            require(set(fields)<=set(declared),'unknown content field')
            require({x['name'] for x in d['fields'] if x['required']}<=set(fields),'missing required content field')
            for k,v in fields.items():
                typ=declared[k]['type'];valid={'string':type(v) is str,'integer':type(v) is int,'boolean':type(v) is bool,'string_set':type(v) is list and all(type(x) is str for x in v)}[typ]
                require(valid,'wrong domain content type')
                if typ=='string_set':require(v==sorted(set(v)),'noncanonical string set')
            slot=json.dumps([fields[x] for x in d['cardinality']['slot_fields']],ensure_ascii=False,separators=(',',':')) if d['cardinality']['mode']=='single' else '[]'
            require(b['slot']==slot,'wrong assertion slot')
            if b['authority_receipt']:exists(b['authority_receipt'],'authority receipt')
        else:require(e['schema'] is None,'non-assertion carries a domain schema')
        if e['kind']=='justification':
            exists(b['target']['assertion'],'justification target')
            for p in b['premises']:exists(p['source'] if p['kind']=='source' else p['literal']['assertion'],'premise')
            if b['check']:exists(b['check'],'rule certificate')
        if e['kind']=='assessment':
            exists(b['pins']['subject'],'assessment subject')
            if b['target']:exists(b['target']['assertion'],'assessment literal')
            for r in b['sources']:exists(r,'assessment source')
        if e['kind']=='revision':
            exists(b['target'],'revision target')
            if b['replacement']:exists(b['replacement'],'replacement')
    for event in s['policy']['authority_events']:
        exists(event['receipt'],'canonical authority event')
        for r in event['predecessors']:exists(r,'authority predecessor')
    for coverage in s['policy']['coverage']:
        exists(coverage['assertion'],'coverage target');exists(coverage['declaration'],'coverage declaration')
    for c in s['runtime']['custody']:
        for r in c['inputs']:exists(r,'custody input')

def check_admission_facts(v):
    # Accepted writes need independently supplied integration facts; deliberate refusals may omit them.
    facts={rkey(f['output']):f for f in v['initial_state']['policy']['lineage_facts']}
    admitted={ref_of(r) for r in v['initial_state']['records']}
    for operation,result in zip(v['operations'],v['expected']['operation_results']):
        if result.get('type')!='receipt':continue
        op=operation['op'];proposals=[]
        if op=='admit':proposals=operation['proposals']
        elif op=='admit_raw':proposals=parse(operation['raw_json'])['proposals']
        elif op=='revise':proposals=[operation['revision']]+([operation['replacement']] if operation['replacement'] else [])
        elif op=='declassify':proposals=operation['assessments']+[operation['output']]
        for proposal in proposals:
            require(ref_of(proposal) in facts,'accepted proposal missing integration fact '+str(ref_of(proposal)))
        available=admitted|{ref_of(p) for p in proposals}
        for proposal in proposals:
            for r in facts[ref_of(proposal)]['inputs']:
                require(rkey(r) in available,'accepted proposal has absent content input '+str(rkey(r)))
        admitted=available

def forbidden_true(report,predicate):
    actual=pointer(report,predicate['path'])
    if actual is MISSING:return False
    test=predicate['test'];wanted=predicate['value']
    if test=='exists':return True
    if test=='equals':return strict_equal(actual,wanted)
    if test=='contains':return isinstance(actual,list) and any(strict_equal(x,wanted) for x in actual)
    if test=='size_equals':return isinstance(actual,list) and type(wanted) is int and len(actual)==wanted
    raise Invalid('unknown forbidden test')

def check_normalization(v):
    n=v['normalization'];report=v['expected'];paths=n['fresh_handles']
    require(len(paths)==len(set(paths)),'duplicate normalized path')
    for p in paths:require(type(pointer(report,p)) is str and re.fullmatch(r'@h[1-9][0-9]*',pointer(report,p)) is not None,'missing symbolic handle at '+p)
    actual_paths=[]
    def scan(x,path=''):
        if isinstance(x,dict):
            for k,val in x.items():
                if k in ['authorized_snapshot_handle','receipt_handle']:actual_paths.append(path+'/'+k)
                scan(val,path+'/'+k)
        elif isinstance(x,list):
            for i,val in enumerate(x):scan(val,path+'/'+str(i))
    scan(report)
    require(set(paths)==set(actual_paths),'normalization does not cover exactly the fresh handle fields')
    for group in n['equal_handles']:
        vals=[pointer(report,p) for p in group];require(len(vals)>1 and all(strict_equal(x,vals[0]) for x in vals),'handle equality constraint failed')
    for group in n['distinct_handles']:
        vals=[pointer(report,p) for p in group];require(len(vals)==len(set(vals)),'fresh handles are not distinct comparison slots')
    normalized=copy.deepcopy(report)
    for p in paths:set_pointer(normalized,p,'<fresh>')
    for pair in n['equivalent_outputs']:
        left=pointer(normalized,pair['left']);right=pointer(normalized,pair['right'])
        require(left is not MISSING and right is not MISSING and strict_equal(left,right),'normalized paired outputs differ')

def check_issuer_local_pairs(vectors):
    # Check the bounded foreign-only fixture edits, not general graph semantics.
    for left_id,right_id in [('S34','S37'),('S36','S38')]:
        left=vectors[left_id];right=vectors[right_id]
        before=left['initial_state'];after=copy.deepcopy(right['initial_state'])
        event=before['policy']['authority_events'][1]
        changed=after['policy']['authority_events'][1]
        issuer=before['projection_rules'][0]['issuer']
        require(event['issuer']!=issuer and changed['issuer']==event['issuer'],'invariance pair does not edit a foreign event')
        require(bool(event['predecessors']) and changed['predecessors']==[],'invariance pair lacks its declared foreign-edge removal')
        changed['predecessors']=copy.deepcopy(event['predecessors'])
        require(strict_equal(before,after),'invariance pair changes more than the foreign predecessor list')
        require(strict_equal(left['query'],right['query']) and strict_equal(left['operations'],right['operations']),'invariance pair changes query or operations')
        require(strict_equal(left['expected'],right['expected']),'invariance pair changes its exact expected report')

def controls(validator,vectors):
    vector=vectors["S01"]
    """Bounded plants prove the checker rejects its claimed structural violations."""
    cases=[]
    def rejected(label,action,needle=None):
        try:action()
        except (Invalid,json.JSONDecodeError) as e:
            if needle is not None and needle not in str(e):raise Invalid('control '+label+' failed for the wrong reason: '+str(e))
            cases.append(label);return
        raise Invalid('control '+label+' was not rejected')
    validator.check(vector,validator.schemas[BASE+'vector']) # Nearby positive control.
    v=copy.deepcopy(vector);v['extra']=True
    rejected('unknown-vector-field',lambda:validator.check(v,validator.schemas[BASE+'vector']),'unknown fields')
    v=copy.deepcopy(vector);del v['query']
    rejected('missing-query',lambda:validator.check(v,validator.schemas[BASE+'vector']),'missing')
    v=copy.deepcopy(vector);v['expected']['result']['items'][0]['support']['witness']='true'
    rejected('invalid-polarity-enum',lambda:validator.check(v,validator.schemas[BASE+'vector']),'enum mismatch')
    v=copy.deepcopy(vector);v['initial_state']['records'][0]['envelope']['recorded']['sequence']=True
    rejected('boolean-is-not-integer',lambda:validator.check(v,validator.schemas[BASE+'vector']),'expected integer')
    rejected('duplicate-key',lambda:parse('{"a":1,"a":2}'),'duplicate JSON key')
    rejected('nonfinite',lambda:parse('{"a":NaN}'),'forbidden JSON number')
    rejected('floating-point',lambda:parse('{"a":1.0}'),'forbidden JSON number')
    v=copy.deepcopy(validator.schemas[BASE+'envelope']);v['additionalProperties']=True
    rejected('open-schema',lambda:validator.closed(v),'not closed')
    rejected('oneOf-overlap',lambda:validator.check('x',{'oneOf':[{'type':'string'},{'type':'string'}]}),'matched 2')
    rejected('out-of-package-reference',lambda:validator.resolve('https://invalid.example/schema'),'unknown package schema')
    v=copy.deepcopy(vector);v['expected']['result']['items'][0]['support']['witness']='present'
    require(forbidden_true(v['expected'],dict(path='/result/items/0/support/witness',test='equals',value='present')),'forbidden predicate plant not detected')
    cases.append('forbidden-outcome')
    domain=copy.deepcopy(vector['initial_state']['domain_schemas'][0]);del domain['fields'][0]['name']
    rejected('domain-required-field',lambda:validator.check(domain,validator.schemas[BASE+'domain-schema']),'missing')
    pair=copy.deepcopy(vectors['S13']);pair['expected']['result']['items'][0]['support']['evaluation']='incomplete'
    rejected('normalization-preserves-semantic-difference',lambda:check_normalization(pair),'paired outputs differ')
    # These plants check admitted integration provenance, owner uniqueness and alias separation.
    documents={schema_ref(d):d for d in vector['initial_state']['domain_schemas']}
    check_state(vector['initial_state'],documents)
    state=copy.deepcopy(vector['initial_state']);state['policy']['lineage_facts'][0]['complete']=False
    state['policy']['lineage_facts'][0]['kind']='model'
    rejected('complete-lineage-needs-integration-evidence',lambda:check_state(state,documents),'lineage differs')
    state=copy.deepcopy(vector['initial_state']);binding=dict(input=dict(id='rec:a',version=1),owners=['owner:a'])
    state['policy']['constraint_owners']=[binding,copy.deepcopy(binding)]
    rejected('one-owner-binding-per-input',lambda:check_state(state,documents),'duplicate constraint owner')
    state=copy.deepcopy(vector['initial_state']);state['policy']['handles']=[dict(subject='a',space='s',audience='p',handle='same'),dict(subject='b',space='s',audience='p',handle='same')]
    rejected('alias-does-not-merge-principals',lambda:check_state(state,documents),'aliases merge')
    # B01 is a regression witness: an accepted revision cannot lack its integration evidence.
    check_admission_facts(vectors['B01'])
    plant=copy.deepcopy(vectors['B01'])
    accepted=next(op for op,result in zip(plant['operations'],plant['expected']['operation_results']) if op['op']=='revise' and result['type']=='receipt')
    target=ref_of(accepted['revision'])
    plant['initial_state']['policy']['lineage_facts']=[f for f in plant['initial_state']['policy']['lineage_facts'] if rkey(f['output'])!=target]
    rejected('accepted-revision-needs-lineage-fact',lambda:check_admission_facts(plant),'accepted proposal missing integration fact')
    # A receipt for B01's prior authority event must trigger its forbidden-output predicate.
    positive=vectors['B01'];report=copy.deepcopy(positive['expected'])
    report['operation_results'][1]=copy.deepcopy(report['operation_results'][6])
    pred=next(x for x in positive['forbidden'] if x['path']=='/operation_results/1/type')
    require(forbidden_true(report,pred),'authority succession forbidden-write plant not detected')
    cases.append('authority-succession-forbidden-write')
    # Issuer-local order plants distinguish contraction, foreign-branch veto and a false receipt.
    for id,path,value,label in [('S34','/result/currentness','current','issuer-local-no-contraction'),('S36','/result/currentness','ambiguous_current','issuer-local-path-survives-foreign-branch'),('S39','/operation_results/0/type','receipt','issuer-local-succession-forbidden-write')]:
        positive=vectors[id];report=copy.deepcopy(positive['expected'])
        pred=next(p for p in positive['forbidden'] if p['path']==path)
        require(not forbidden_true(report,pred),'issuer-local positive control is forbidden')
        set_pointer(report,path,value)
        require(forbidden_true(report,pred),'issuer-local forbidden-output plant not detected')
        cases.append(label)
    check_issuer_local_pairs(vectors)
    plant=copy.deepcopy(vectors)
    plant['S37']['initial_state']['policy']['authority_events'][2]['predecessors']=[]
    rejected('invariance-pair-preserves-H-subgraph',lambda:check_issuer_local_pairs(plant),'changes more than the foreign predecessor list')
    state=copy.deepcopy(vector['initial_state']);state['runtime']['dirty']=[dict(id='rec:a',version=1)]
    rejected('dirty-needs-unresolved-cause',lambda:check_state(state,documents),'dirty inventory lacks')
    # Valid initial own attribution passes; foreign self-declaration fails without identity coercion.
    positive=vectors['P02']['initial_state'];docs={schema_ref(d):d for d in positive['domain_schemas']}
    check_state(positive,docs)
    state=copy.deepcopy(positive);e=state['records'][0]['envelope']
    e.update(issuer='principal:foreign',submitter='principal:foreign',perspective=dict(kind='own',principal='principal:foreign'))
    rejected('initial-self-declaration-requires-identity',lambda:check_state(state,docs),'self-declaration lacks subject issuer identity')
    state=copy.deepcopy(positive);state['policy']['subject_principals']=[]
    rejected('equal-id-spelling-is-not-identity',lambda:check_state(state,docs),'self-declaration lacks subject issuer identity')
    # Erase receipts require an exact context; a recipient override and hidden refs are forbidden.
    erase_schema=next(x for x in validator.schemas[BASE+'vector']['properties']['operations']['items']['oneOf'] if x['properties']['op'].get('const')=='erase')
    positive=vectors['P08'];validator.check(positive,validator.schemas[BASE+'vector'])
    op=copy.deepcopy(positive['operations'][0]);del op['receipt_context']
    rejected('erase-requires-receipt-context',lambda:validator.check(op,erase_schema),"missing ['receipt_context']")
    op=copy.deepcopy(positive['operations'][0]);op['receipt_context']['recipient']='principal:other'
    rejected('erase-recipient-cannot-be-overridden',lambda:validator.check(op,erase_schema),"unknown fields ['recipient']")
    report=copy.deepcopy(positive['expected']);report['operation_results'][0]['refs'].append(dict(id='rec:summary',version=1))
    pred=next(x for x in positive['forbidden'] if x['path']=='/operation_results/0/refs/1/id')
    require(forbidden_true(report,pred),'erasure receipt hidden-ref plant not detected')
    cases.append('erasure-receipt-hidden-reference')
    # Every closed storage operation needs context, and actor identity cannot be overridden.
    variants=validator.schemas[BASE+'vector']['properties']['operations']['items']['oneOf']
    for name in ['admit','admit_raw','revise','declassify']:
        schema=next(x for x in variants if x['properties']['op'].get('const')==name)
        positive=next(o for v in vectors.values() for o in v['operations'] if o['op']==name)
        validator.check(positive,schema)
        op=copy.deepcopy(positive);del op['context']['retention_context']
        rejected(name+'-requires-retention-context',lambda:validator.check(op,schema),"missing ['retention_context']")
    positive=vectors['P11'];validator.check(positive,validator.schemas[BASE+'vector'])
    schema=next(x for x in variants if x['properties']['op'].get('const')=='admit')
    op=copy.deepcopy(positive['operations'][8]);op['context']['retention_context']['principal']='principal:other'
    rejected('retention-principal-cannot-be-overridden',lambda:validator.check(op,schema),"unknown fields ['principal']")
    report=copy.deepcopy(positive['expected']);report['operation_results'][0]=copy.deepcopy(report['operation_results'][8])
    pred=next(x for x in positive['forbidden'] if x['path']=='/operation_results/0/type')
    require(forbidden_true(report,pred),'retention unauthorized-write plant not detected')
    cases.append('retention-unauthorized-write')
    # The expiry boundary must reject replay even though the original receipt was authorized.
    report=copy.deepcopy(positive['expected'])
    report['operation_results'][18]=copy.deepcopy(report['operation_results'][16])
    pred=next(x for x in positive['forbidden'] if x['path']=='/operation_results/18/type')
    require(forbidden_true(report,pred),'expired-retention replay plant not detected')
    cases.append('expired-retention-replay')
    # Future facts are permitted; accepted batches and admitted snapshots still require actual inputs.
    positive=vectors['P13'];docs={schema_ref(d):d for d in positive['initial_state']['domain_schemas']}
    check_state(positive['initial_state'],docs);check_admission_facts(positive)
    plant=copy.deepcopy(positive)
    plant['operations'][2]['proposals']=[p for p in plant['operations'][2]['proposals'] if p['envelope']['id']!='rec:model-stage']
    rejected('accepted-batch-needs-actual-input',lambda:check_admission_facts(plant),'accepted proposal has absent content input')
    for complete in [True,False]:
        state=copy.deepcopy(vector['initial_state']);e=state['records'][0]['envelope']
        fact=next(f for f in state['policy']['lineage_facts'] if rkey(f['output'])==(e['id'],e['version']))
        missing=dict(id='rec:absent-content-input',version=1)
        fact.update(kind='model',complete=complete,inputs=[missing]);e['lineage']=[missing] if complete else 'unknown'
        docs={schema_ref(d):d for d in state['domain_schemas']}
        rejected('admitted-input-must-exist-'+str(complete),lambda:check_state(state,docs),'dangling integration input')
    return len(cases)

def main():
    loaded={}
    for p in sorted(ROOT.rglob('*.json')):
        try:loaded[p]=parse(p.read_text(encoding='utf-8'))
        except (ValueError,OSError) as e:ERRORS.append(f'{p.relative_to(ROOT)}: {e}')
    schemas={}
    for p,x in loaded.items():
        if p.parent==ROOT/'kernel'/'schemas':
            if x.get('$id') in schemas:ERRORS.append('duplicate schema $id')
            schemas[x.get('$id')]=x
    validator=Validator(schemas)
    for uri,s in schemas.items():
        try:
            require(s.get('$schema')=='https://json-schema.org/draft/2020-12/schema','wrong schema dialect')
            require(type(uri) is str and uri.startswith(BASE),'invalid schema id')
            validator.closed(s)
        except Invalid as e:ERRORS.append(f'{uri}: {e}')
    documents={};fixtures=[]
    for p,d in loaded.items():
        if 'domains' not in p.relative_to(ROOT).parts:continue
        try:
            if p.name=='fixture.json':fixtures.append((p,d));continue
            validator.check(d,schemas[BASE+'domain-schema']);check_domain(d)
            require(schema_ref(d) not in documents,'duplicate canonical domain document')
            documents[schema_ref(d)]=d
        except (Invalid,KeyError) as e:ERRORS.append(f'{p.relative_to(ROOT)}: {e}')
    semantics=(ROOT/'kernel'/'semantics.md').read_text()
    clauses=re.findall(r'^### (K-[A-Z]+-\d+) — ',semantics,re.M)
    require(len(clauses)==len(set(clauses)),'duplicate normative clause id')
    vectors={}
    for p,v in loaded.items():
        if p.parent.parent!=ROOT/'kernel'/'vectors':continue
        try:
            validator.check(v,schemas[BASE+'vector'])
            require(v['id']==p.stem,'vector filename/id mismatch')
            require(v['profile']==p.parent.name,'profile/directory mismatch')
            require(v['id'] not in vectors,'duplicate vector id')
            vectors[v['id']]=v
            require(bool(v['clauses']) and len(v['clauses'])==len(set(v['clauses'])),'empty or duplicate vector clauses')
            require(set(v['clauses'])<=set(clauses),'unknown normative clause')
            require(len(v['operations'])==len(v['expected']['operation_results']),'operation/result count mismatch')
            check_state(v['initial_state'],documents)
            check_admission_facts(v)
            for pred in v['forbidden']:require(not forbidden_true(v['expected'],pred),'expected output satisfies forbidden predicate '+pred['path'])
            check_normalization(v)
        except (Invalid,KeyError) as e:ERRORS.append(f'{p.relative_to(ROOT)}: {e}')
    for p,f in fixtures:
        try:validator.check(f,schemas[BASE+'fixture']);check_state(f['initial_state'],documents)
        except (Invalid,KeyError) as e:ERRORS.append(f'{p.relative_to(ROOT)}: {e}')
    expected_ids={f'S{i:02d}' for i in range(1,43)}|{f'P{i:02d}' for i in range(1,16)}|{f'B{i:02d}' for i in range(1,18)}
    if set(vectors)!=expected_ids:ERRORS.append('vector inventory mismatch: '+str(sorted(expected_ids^set(vectors))))
    try:check_issuer_local_pairs(vectors)
    except (Invalid,KeyError) as e:ERRORS.append('issuer-local invariance pair: '+str(e))
    coverage=(ROOT/'COVERAGE.md').read_text()
    rows=[]
    for line in coverage.splitlines():
        m=re.match(r'^\| ([SPB]\d{2}) \| (.*?) \| (.*?) \| (.*?) \|$',line)
        if m:rows.append(m.groups())
    ids=[r[0] for r in rows]
    if set(ids)!=expected_ids or len(ids)!=len(set(ids)):ERRORS.append('coverage ids missing, extra or repeated')
    used=set()
    for id,profile,cs,source in rows:
        if id not in vectors:continue
        refs=set(re.findall(r'K-[A-Z]+-\d+',cs));used.update(refs)
        if refs!=set(vectors[id]['clauses']):ERRORS.append(id+': coverage clauses disagree with vector')
        if profile!=vectors[id]['profile']:ERRORS.append(id+': coverage profile disagrees with vector')
        if not source.strip():ERRORS.append(id+': missing source citation')
    exempt=set(re.findall(r'^\| (K-[A-Z]+-\d+) \| not vector-tested \| .+ \|$',coverage,re.M))
    if set(clauses)-(used|exempt):ERRORS.append('clauses lack vector or explicit reason: '+str(sorted(set(clauses)-(used|exempt))))
    # Public kernel hygiene: package-relative schema references are URNs, never host paths.
    forbidden_terms=re.compile(r'\b(swarma|curator|board|dispatcher|session[- ]host|a2a|astra[- ]?\d+|wonder[- ]?\d+)\b|/(?:Users|private|home)/',re.I)
    for p in (ROOT/'kernel').rglob('*'):
        if p.is_file() and forbidden_terms.search(p.read_text()):ERRORS.append(str(p.relative_to(ROOT))+': platform/private term in kernel')
    count_controls=0
    try:count_controls=controls(validator,vectors)
    except (Invalid,KeyError) as e:ERRORS.append('checker control failure: '+str(e))
    if ERRORS:
        for e in ERRORS:print('FAIL '+e)
        print(f'FAILED: {len(ERRORS)} error(s).');return 1
    semantic=sum(x['profile']=='semantic' for x in vectors.values())
    print(f'PASS: {len(loaded)} JSON files parsed; {len(schemas)} closed schemas; {len(documents)} domain documents; {len(fixtures)} fixture corpus.')
    print(f'PASS: {len(vectors)} vectors ({semantic} semantic, {len(vectors)-semantic} deployment); {len(clauses)} normative clauses covered; coverage IDs unique.')
    print(f'PASS: references, forbidden predicates, normalization pairs, kernel hygiene; {count_controls} checker controls detected their intended violations.')
    print('RESULT: structural package validation passed. Evaluator semantics and protected deployment behavior were not executed.')
    return 0

if __name__=='__main__':
    try:sys.exit(main())
    except (Invalid,OSError,KeyError) as e:print('FAIL '+str(e));sys.exit(1)
