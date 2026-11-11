#!/usr/bin/env python3
"""Generate original SVG report figures from the committed evidence and mapping."""
from pathlib import Path
import json,html,argparse
ROOT=Path(__file__).resolve().parents[1]

def text(x,y,value,size=20,color='#172033',weight='normal'):
 return f'<text x="{x}" y="{y}" font-family="DejaVu Sans,Arial,sans-serif" font-size="{size}" fill="{color}" font-weight="{weight}">{html.escape(str(value))}</text>'
def start(w,h):return f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}"><rect width="100%" height="100%" fill="white"/>'
def box(x,y,w,h,fill):return f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="8" fill="{fill}"/>'

def main():
 p=argparse.ArgumentParser();p.add_argument('evidence',type=Path);args=p.parse_args()
 m=json.loads((ROOT/'data/week10/apt29-mapping.json').read_text())
 s=start(1160,670)+text(30,42,'APT29 selected techniques and project evidence',28,weight='bold')+text(30,75,'Source-backed CTI is separate from laboratory validation',19,color='#475569')
 s+=box(25,100,1110,44,'#172033')+text(40,129,'ATT&CK',18,'white')+text(200,129,'Technique',18,'white')+text(750,129,'Project evidence',18,'white')
 labels={'cti_only':'CTI only / not validated','historical_lab':'Historical Windows lab','portable_lab':'Linux archive analogue'}
 colors={'cti_only':'#CBD5E1','historical_lab':'#93C5FD','portable_lab':'#FCD34D'}
 for i,row in enumerate(m['techniques']):
  y=149+i*44
  s+=box(25,y,1110,40,'#F1F5F9' if i%2==0 else '#FFFFFF')+text(40,y+27,row['technique_id'],18)
  name=row['name'].replace('Exfiltration Over Asymmetric Encrypted Non-C2 Protocol','Asymmetric encrypted non-C2 exfiltration')
  s+=text(200,y+27,name,18)+box(735,y+4,380,32,colors[row['evidence_status']])+text(750,y+27,labels[row['evidence_status']],17)
 s+=text(30,624,'ATT&CK v20.1 checked 8 Nov 2026. Colors are evidence labels, not detection scores.',17,color='#475569')+'</svg>'
 (ROOT/'images/week10/apt29-coverage.svg').write_text(s)
 summary=json.loads((args.evidence/'siem/summary.json').read_text())
 s=start(1120,540)+text(30,43,'Week 9 actual Elasticsearch query results',28,weight='bold')+text(30,76,'Observed execve events from 3 atomics and 2 benign controls',19,color='#475569')
 version=summary.get('query_version',1)
 revised=version>=2
 if revised:
  s=start(1120,540)+text(30,43,'Revised Week 9 archive hunt',28,weight='bold')+text(30,76,'Three Atomic Red Team procedures and six controls on Linux',19,color='#475569')
 titles=['All observed executions','Archive utility executions','Archive with lab source path'];keys=['inventory','archive_utility','lab_browser_archive']
 if revised:
  titles=['Archive utility executions','Original path filter','Creation and profile open']
  keys=['archive_utility','legacy_path','lab_browser_archive']
 if version==3:
  s=start(1120,540)+text(30,43,'Week 9 archive attempts and exit status',28,weight='bold')+text(30,76,'Observed create invocations with a registered profile input open',19,color='#475569')
  titles=['Profile archive attempts','Archiver exited successfully','Archiver exited with an error']
  keys=['profile_archive_attempt','lab_browser_archive','failed_profile_archive']
 for i,(name,k) in enumerate(zip(titles,keys)):
  y=125+i*100;count=summary['counts'][k]
  s+=text(30,y+30,name,21)+box(445,y,max(15,580*count/summary['counts'][keys[0]]),48,['#64748B','#2563EB','#0F766E'][i])+text(1045,y+33,count,28,weight='bold')
 s+=text(30,450,(f'Each search was run on the same {summary["counts"]["inventory"]} process events.' if revised else 'Broad matches include ordinary backup activity; refined matches use a lab-specific path.'),18,color='#475569')
 s+=text(30,487,'Counts represent events, not malware detections. Source: siem/results.json.',18,color='#475569')+'</svg>'
 (ROOT/'images/week9'/(f'query-results-v{version}.svg' if revised else 'query-results.svg')).write_text(s)
 s=start(1120,390)+text(30,43,'Week 9 evidence pipeline',28,weight='bold')
 steps=[('Pinned atomics',['3 reviewed commands','Synthetic local files']),('Native traces',['strace child processes','execve and file calls']),('Elasticsearch',['New isolated indices','Queries and controls']),('Evidence package',['API responses and hashes','Reports and defense'])]
 for i,(title,lines) in enumerate(steps):
  x=25+i*280;s+=box(x,105,250,165,'#EFF6FF')+text(x+15,145,title,22,weight='bold')
  for j,line in enumerate(lines):s+=text(x+15,185+34*j,line,17)
  if i<3:s+=text(x+253,195,'→',25,'#2563EB')
 s+=text(30,330,'Linux execution only. Historical Windows evidence remains separate.',19,color='#475569')+'</svg>'
 (ROOT/'images/week9/evidence-pipeline.svg').write_text(s)
 print('Generated 3 evidence-based SVG figures')
if __name__=='__main__':main()
