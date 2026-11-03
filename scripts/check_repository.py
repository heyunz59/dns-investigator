"""Current-tree documentation, metadata and size checks; no network/model calls."""
import json
import re
import subprocess
import tomllib
from pathlib import Path
from urllib.parse import unquote


def main():
    root=Path(__file__).resolve().parents[1]
    names=subprocess.check_output(['git','ls-files','-z'],cwd=root).decode('utf8').split('\0')
    names=[n for n in names if n and (root/n).is_file()]
    issues=[];links=0
    for name in names:
        p=root/name
        if p.stat().st_size>5_000_000:issues.append(name+': exceeds 5 MB current-tree limit')
        if name.startswith('results/') and name!='results/README.md':issues.append(name+': generated output tracked')
        if p.suffix!='.md':continue
        text=re.sub(r'```.*?```','',p.read_text(encoding='utf-8-sig'),flags=re.S)
        for target in re.findall(r'\]\(([^\s)]+)(?:\s+[^)]*)?\)',text):
            if re.match(r'[a-zA-Z][a-zA-Z0-9+.-]*:|#',target):continue
            target=unquote(target.split('#')[0]);links+=1
            if target and not (p.parent/target).exists():issues.append(name+': missing relative link '+target)
    cfg=tomllib.loads((root/'pyproject.toml').read_text(encoding='utf8'))
    assert 'version' in cfg['project']['dynamic'] and 'version' not in cfg['project']
    assert cfg['project']['license']=='MIT' and (root/'LICENSE').exists()
    for name in ('README.md','README.zh-CN.md'):
        assert 'chore/open-source-release-prep' in (root/name).read_text(encoding='utf8')
    print(json.dumps(dict(status='FAIL' if issues else 'PASS',checked_files=len(names),relative_links=links,issues=issues),ensure_ascii=False))
    return bool(issues)


if __name__=='__main__':raise SystemExit(main())
