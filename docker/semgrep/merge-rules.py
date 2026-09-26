"""Merge each rule directory into one YAML file, keeping every rule id as Semgrep derives it.

Semgrep spends most of a scan's wall time loading rules from many small files (26 s of a 26 s scan
of an empty Python repo with the 337 community files; 1 s when they are one file). Semgrep names a
rule from its path (`python.django.security.x` for /rules/python/django/security/foo.yaml), so the
id is written into the merged rule to keep findings, correlation keys and docs identical.
"""

import sys
from pathlib import Path

from ruamel.yaml import YAML

src, dst = Path(sys.argv[1]), Path(sys.argv[2])
yaml = YAML(typ="safe")
yaml.default_flow_style = False
dst.mkdir(parents=True)
for lang in sorted(p for p in src.iterdir() if p.is_dir()):
    rules = []
    for f in sorted(lang.rglob("*.y*ml")):
        if f.name.endswith((".test.yaml", ".test.yml", ".fixed.yaml")):
            continue
        doc = yaml.load(f.read_text())
        if not isinstance(doc, dict):
            continue
        prefix = ".".join(f.relative_to(src).parent.parts)
        for r in doc.get("rules") or []:
            r["id"] = f"{prefix}.{r['id']}"
            rules.append(r)
    with (dst / f"{lang.name}.yaml").open("w") as out:
        yaml.dump({"rules": rules}, out)
    print(f"{lang.name}: {len(rules)} rules")
