"""Reproducible engineering calibration; never executes samples.

python -m scfs.calibration [--benign-file PATH ...] [--manifest corpus.json]
Manifest: {"samples":[{"path":"file.exe","label":"benign|malicious",
                       "split":"validation|test"}]}
Labels in a user manifest are provided by the user, not established by scfs.
"""
import argparse
import json
from pathlib import Path
from . import run_engine
from .scoring.sigmoid import sigmoid

CANDIDATES=(4.5,5.0,6.0,7.0)

def controls():
    return json.loads((Path(__file__).parent/'datasets'/'controls.json').read_text())

def evaluate(benign_files=(),manifest=None):
    builtins=[]
    for case in controls():
        scan,_=run_engine(case['text'].encode(),name=case['name'])
        builtins.append(dict(case,raw_score=scan['scoring']['raw_score']))
    samples=[]
    if manifest:
        manifest=Path(manifest)
        for item in json.loads(manifest.read_text())['samples']:
            if item['label'] not in ('benign','malicious') or item.get('split') not in ('validation','test'):
                raise ValueError('manifest requires label benign/malicious and split validation/test')
            path=Path(item['path'])
            if not path.is_absolute():path=manifest.parent/path
            samples.append((path,item['label'],item['split']))
    samples.extend((Path(p),'benign','test') for p in benign_files)
    observed=[]
    seen={}
    for path,label,split in samples:
        scan,target=run_engine(path)
        if scan['status'] in ('error','inconclusive'):
            observed.append(dict(name=path.name,label=label,split=split,status=scan['status'],error=scan.get('error')))
            continue
        digest=target['identity']['sha256']
        if digest in seen:
            if seen[digest] != (label,split):
                raise ValueError('same hash has conflicting labels or crosses validation/test split')
            continue
        seen[digest]=(label,split)
        observed.append(dict(name=path.name,label=label,split=split,status=scan['status'],sha256=digest,
                             format=target['executable']['format'],raw_score=scan['scoring']['raw_score'],warnings=scan.get('warnings',[])))
    evaluations=[]
    for k in CANDIDATES:
        checks=[]
        # Explicit curve specifications; these are policy targets, not learned malware probabilities.
        curve=dict(neutral_below_10=sigmoid([0],[1],k)<10,
                   strong_at_least_85=sigmoid([.85],[1],k)>=85,
                   isolated_strong_is_suspicious=25<=sigmoid([.35],[1],k)<55)
        for case in builtins:
            score=sigmoid([case['raw_score']],[1],k)
            checks.append(dict(id=case['id'],split=case['split'],score=round(score,4),
                               passed=case['minimum']<=score<case['maximum']))
        validation_failures=sum(not c['passed'] for c in checks if c['split']=='validation')
        metrics={}
        for split in ('validation','test'):
            usable=[r for r in observed if r.get('raw_score') is not None and r['split']==split]
            metrics[split]=dict(benign=sum(r['label']=='benign' for r in usable),
                malicious=sum(r['label']=='malicious' for r in usable),
                benign_flagged=sum(r['label']=='benign' and sigmoid([r['raw_score']],[1],k)>=25 for r in usable),
                malicious_below_threshold=sum(r['label']=='malicious' and sigmoid([r['raw_score']],[1],k)<25 for r in usable))
        evaluations.append(dict(k=k,curve_checks=curve,controls=checks,validation_failures=validation_failures,
                               corpus_metrics=metrics,accepted=all(curve.values()) and validation_failures==0))
    accepted=[r for r in evaluations if r['accepted']]
    # Validation loss selects among accepted candidates. Test/holdout do not select k.
    def validation_loss(row):
        metrics=row['corpus_metrics']['validation']
        # Explicit policy: one false alarm costs five times one miss.
        return (5 * metrics['benign_flagged']/max(metrics['benign'],1)
                + metrics['malicious_below_threshold']/max(metrics['malicious'],1))
    selected=min(accepted,key=lambda row:(validation_loss(row),row['k']))['k'] if accepted else None
    for row in observed:
        if selected and row.get('raw_score') is not None:
            row['score']=round(sigmoid([row['raw_score']],[1],selected),2)
    return dict(scope='engineering_controls_and_user_labeled_static_corpus',empirically_calibrated=False,
                selected_k=selected,selection='engineering constraints, then validation loss (5*FPR + FNR when labels exist), then smallest k; holdout/test excluded',
                rule_count=25,candidates=evaluations,corpus=observed,
                limitations=['Synthetic controls are not malware samples.',
                             'Installed binaries are assumed legitimate; provenance is not verified by this tool.',
                             'No malware detection accuracy can be inferred without an independent labeled malicious corpus.',
                             'Changing k cannot repair missing or incorrect heuristics.'])

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--benign-file',action='append',default=[],type=Path)
    parser.add_argument('--manifest',type=Path)
    args=parser.parse_args()
    try:report=evaluate(args.benign_file,args.manifest)
    except (OSError,ValueError,KeyError) as exc:parser.error(str(exc))
    print(json.dumps(report,indent=2,ensure_ascii=True))
    return 0 if report['selected_k'] is not None else 1

if __name__=='__main__':raise SystemExit(main())
