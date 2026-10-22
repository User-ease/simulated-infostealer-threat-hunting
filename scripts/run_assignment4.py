"""Validate the local collection and execute the disclosed CAR adaptation in Elastic."""
import argparse
import hashlib
import json
from pathlib import Path
from urllib.request import Request, urlopen
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
CAR = {'bool': {'filter': [
    {'term': {'event.dataset': 'lab.process_inventory'}},
    {'term': {'process.name': 'powershell.exe'}},
    {'exists': {'field': 'process.parent.name'}}],
    'must_not': [{'term': {'process.parent.name': 'explorer.exe'}},
                 {'term': {'process.parent.name': ''}}]}}

def read(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))

def save(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False)+'\n', encoding='utf-8')

def mapping():
    name_field={'type': 'keyword', 'normalizer': 'windows_name'}
    properties={
        '@timestamp': {'type': 'date'},
        'event': {'properties': {'dataset': {'type': 'keyword'}, 'id': {'type': 'keyword'}, 'action': {'type': 'keyword'}}},
        'lab': {'properties': {'case': {'type': 'keyword'}, 'run_id': {'type': 'keyword'}}},
        'process': {'properties': {'name': name_field, 'parent': {'properties': {'name': name_field}}}},
    }
    settings={'number_of_shards': 1, 'number_of_replicas': 0,
              'analysis': {'normalizer': {'windows_name': {'type': 'custom', 'filter': ['lowercase']}}}}
    return {'settings': settings, 'mappings': {'properties': properties}}

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('collection', type=Path)
    args=parser.parse_args()
    run=args.collection.resolve()
    manifest=read(run/'collection-manifest.json')
    for item in read(run/'collection-sha256.json'):
        p=(run/item['file']).resolve()
        if p.parent != run or hashlib.sha256(p.read_bytes()).hexdigest().lower()!=item['sha256'].lower():
            raise ValueError('Collection integrity check failed')
    if hashlib.sha256((ROOT/'scripts/collect_assignment4.ps1').read_bytes()).hexdigest().lower()!=manifest['collector_sha256'].lower():
        raise ValueError('Collector hash differs from collection manifest')
    docs=[json.loads(s) for s in (run/'process-observations.jsonl').read_text(encoding='utf-8-sig').splitlines() if s.strip()]
    labels=read(run/'case-labels.json')
    expected={r['case'] for r in labels if r['expected_car_match']}
    index='lab-assignment4-'+manifest['run_id'].lower()
    transcript=[]
    def api(service, method, path, body=None, ndjson=False):
        base={'es':'http://127.0.0.1:19200','kibana':'http://127.0.0.1:15601'}[service]
        data=(body.encode() if ndjson else json.dumps(body).encode()) if body is not None else None
        req=Request(base+path, data=data, method=method, headers={'Content-Type':'application/x-ndjson' if ndjson else 'application/json','kbn-xsrf':'assignment4'})
        with urlopen(req, timeout=90) as response:
            result=json.loads(response.read())
            transcript.append({'utc':datetime.now(timezone.utc).isoformat(),'service':service,'method':method,'path':path,'request':body,'status':response.status,'response':result})
        save(run/'siem-api-transcript.json',transcript)
        return result
    def ingest(name, rows):
        api('es','PUT','/'+name,mapping())
        bulk=''.join(json.dumps({'create':{'_index':name,'_id':str(i)}})+'\n'+json.dumps(row)+'\n' for i,row in enumerate(rows))
        result=api('es','POST','/_bulk?refresh=true',bulk,True)
        if result.get('errors'): raise ValueError('Bulk indexing failed')
    runtime={'elasticsearch':api('es','GET','/'),'kibana':api('kibana','GET','/api/status')}
    save(run/'siem-runtime.json',runtime)
    ingest(index,docs)
    queries={'inventory':{'match_all':{}},'powershell':{'term':{'process.name':'powershell.exe'}},'car_adapted':CAR}
    save(run/'hunt-queries.json',queries)
    results={name:api('es','POST','/'+index+'/_search',{'size':100,'track_total_hits':True,'query':q}) for name,q in queries.items()}
    actual={h['_source']['lab']['case'] for h in results['car_adapted']['hits']['hits']}
    if actual != expected: raise AssertionError(f'CAR case mismatch: {actual} != {expected}')
    if results['inventory']['hits']['total']['value']!=3 or results['powershell']['hits']['total']['value']!=2:
        raise AssertionError('Unexpected collection counts')
    save(run/'hunt-results.json',results)
    # Explicit synthetic boundary checks are isolated from the observed Windows data.
    fixture_specs=[('automation','powershell.exe','pwsh.exe',True),('explorer','powershell.exe','explorer.exe',False),('cmd','cmd.exe','pwsh.exe',False),('missing','powershell.exe',None,False),('empty','powershell.exe','',False),('uppercase','POWERSHELL.EXE','CMD.EXE',True)]
    fixtures=[]
    for name,exe,parent,match in fixture_specs:
        proc={'name':exe}
        if parent is not None: proc['parent']={'name':parent}
        fixtures.append({'event':{'dataset':'lab.process_inventory'},'process':proc,'lab':{'case':name},'fixture':True})
    fixture_index=index+'-regression'
    ingest(fixture_index, fixtures)
    checks=api('es','POST','/'+fixture_index+'/_search',{'size':100,'query':CAR})
    matched={h['_source']['lab']['case'] for h in checks['hits']['hits']}
    wanted={name for name,exe,parent,match in fixture_specs if match}
    if matched != wanted: raise AssertionError('Synthetic boundary checks failed')
    save(run/'regression-results.json',{'source':'Explicit synthetic fixtures; separate index; not observed endpoint events','index':fixture_index,'cases':[{'case':name,'expected':match,'actual':name in matched} for name,exe,parent,match in fixture_specs],'response':checks})
    view_id=index
    view=api('kibana','POST','/api/data_views/data_view',{'data_view':{'id':view_id,'title':index,'name':'Assignment 4 - observed Windows processes','timeFieldName':'@timestamp'}})
    summary={'status':'passed','run_id':manifest['run_id'],'index':index,'data_view_id':view_id,'counts':{k:v['hits']['total']['value'] for k,v in results.items()},'matched_cases':sorted(actual),'boundary_checks_passed':len(fixture_specs),'telemetry_scope':'CAR predicate adapted to lab.process_inventory observations; not Sysmon process creation or continuous production detection','week6':'Harmless PowerShell marker and mock-file staging completed','week7':'CAR selection implemented and executed in Elasticsearch; Kibana data view created','completed_utc':datetime.now(timezone.utc).isoformat()}
    save(run/'validation-summary.json',summary)
    save(run/'siem-sha256.json',[{'file':p.name,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in run.iterdir() if p.is_file() and p.name!='siem-sha256.json'])
    print(json.dumps(summary,indent=2))

if __name__=='__main__': main()
