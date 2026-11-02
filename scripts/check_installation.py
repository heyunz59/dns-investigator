"""Exercise real editable/wheel installations outside the checkout, without model/network probes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def run(cmd,**kwargs):
    env=kwargs.setdefault('env',os.environ.copy());env['PYTHONUTF8']='1'
    return subprocess.run(cmd,text=True,encoding='utf-8',capture_output=True,timeout=180,**kwargs)


def verify(root,kind,cwd):
    env=os.environ.copy();env.pop('PYTHONPATH',None)
    py=Path(sys.executable)
    console=py.parent/('dns-investigator.exe' if os.name=='nt' else 'dns-investigator')
    assert console.exists(), 'Installed console entry point missing'
    probe=run([str(py),'-c','import dns_investigator; print(dns_investigator.__file__)'],cwd=cwd,env=env)
    assert probe.returncode==0,probe.stderr
    installed=Path(probe.stdout.strip()).resolve().parent
    assert installed.is_relative_to(root/'src')==(kind=='editable'), 'Wrong package import location'
    inventory={}
    for source in (root/'src/dns_investigator').rglob('*'):
        if not source.is_file() or '__pycache__' in source.parts or source.suffix=='.pyc':continue
        relative=source.relative_to(root/'src/dns_investigator');target=installed/relative
        assert target.exists(),str(relative)
        assert target.read_bytes()==source.read_bytes(),str(relative)
        inventory[relative.as_posix()]=hashlib.sha256(target.read_bytes()).hexdigest()
    cases=[(['--format','json','--help'],0),(['--format','json'],2),
        (['--format','json','--verbose'],2),(['--target','https://u:p@example.com','--format','json'],2),
        (['query example.com A','--tools-only','--fixture',str(root/'data/fixtures/Q1.json'),'--format','json'],0)]
    results=[]
    for entry,prefix in [('module',[str(py),'-m','dns_investigator.main']),('console',[str(console)])]:
        for i,(args,code) in enumerate(cases):
            result=run(prefix+args,cwd=cwd,env=env,input='')
            assert result.returncode==code,(kind,entry,i,result.returncode,result.stderr)
            obj=json.loads(result.stdout) # rejects banners or a second object
            assert isinstance(obj,dict)
            if i==4:assert obj['mode']=='tools_only' and obj['evidence']
            results.append(dict(entry=entry,case=i,exit_code=result.returncode,json_object=True,status=obj['status']))
    return dict(kind=kind,import_location='checkout/src' if kind=='editable' else 'installed site-packages',
        module_and_asset_hashes=inventory,cli_cases=results,PYTHONPATH='removed',cwd='temporary directory outside checkout')


def main():
    p=argparse.ArgumentParser();p.add_argument('--wheel-dir',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--restore-editable',action='store_true');args=p.parse_args()
    root=Path(__file__).resolve().parents[1]
    wheels=list(args.wheel_dir.resolve().glob('dns_investigator-*.whl'));assert len(wheels)==1
    result=dict(python=sys.version.split()[0],platform=sys.platform,model_calls=0,network_measurements=0,
        dependency_environment='existing installed dependencies retained; actual project install replaced for each phase',
        wheel_sha256=hashlib.sha256(wheels[0].read_bytes()).hexdigest(),phases=[])
    with tempfile.TemporaryDirectory(prefix='dns-install-check-') as cwd:
        result['phases'].append(verify(root,'editable',cwd))
        installed=run([sys.executable,'-m','pip','install','--no-deps','--force-reinstall',str(wheels[0])])
        assert installed.returncode==0,installed.stderr
        try:result['phases'].append(verify(root,'wheel',cwd))
        finally:
            if args.restore_editable:
                restored=run([sys.executable,'-m','pip','install','--no-deps','-e',str(root)])
                assert restored.returncode==0,restored.stderr
                result['editable_restored']=True
    result['status']='PASS';args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print('Installation verification PASS: editable + wheel; both entry points; 20 strict JSON CLI cases; all module/assets match.')


if __name__=='__main__':main()
