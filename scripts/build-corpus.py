#!/usr/bin/env python3
"""Build the local remediation corpus (Week 11): CWE descriptions + OWASP cheat-sheet sections.

Needs the network (curl); the RESULT is committed under core/rag/corpus/, so nothing else in Bulwark does.
Sources are pinned in SOURCES.json (CWE catalog version, cheat-sheet commit) so a rebuild is auditable.

    python scripts/build-corpus.py            # rebuild core/rag/corpus/*.jsonl

Licences: CWE (c) MITRE, used under the CWE terms of use; OWASP Cheat Sheet Series and Top 10 are
CC BY-SA. See core/rag/corpus/NOTICE.md. The corpus is reference text for prompts, never scanner output.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "core" / "rag" / "corpus"
sys.path.insert(0, str(ROOT))

CWE_ZIP = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
CS_RAW = "https://raw.githubusercontent.com/OWASP/CheatSheetSeries/{sha}/cheatsheets/{name}_Cheat_Sheet.md"
CS_COMMIT = "https://api.github.com/repos/OWASP/CheatSheetSeries/commits/master"
CS_PAGE = "https://cheatsheetseries.owasp.org/cheatsheets/{name}_Cheat_Sheet.html"

# CWEs scanners emitted in our real scans but OWASP's Top 10 table does not list, plus classic memory bugs.
EXTRA_CWES = [
    1321, 400, 1333, 770, 843, 407, 248, 697, 125, 405, 674, 1050, 754, 789, 703, 126, 693, 367, 704,
    941, 27, 399, 190, 427, 792, 787, 476, 416, 120, 134,
]  # fmt: skip

# Curated: cheat sheet -> OWASP Top 10:2021 categories and the CWEs it directly addresses. This is a
# judgment call (documented in docs/rag.md), used for retrieval filtering, not asserted by OWASP.
SHEETS: dict[str, tuple[list[str], list[int]]] = {
    "SQL_Injection_Prevention": (["A03:2021"], [89]),
    "Query_Parameterization": (["A03:2021"], [89]),
    "Injection_Prevention": (["A03:2021"], [74, 77, 78, 89, 90, 91, 94]),
    "Injection_Prevention_in_Java": (["A03:2021"], [89, 78]),
    "OS_Command_Injection_Defense": (["A03:2021"], [78, 77]),
    "LDAP_Injection_Prevention": (["A03:2021"], [90]),
    "Cross_Site_Scripting_Prevention": (["A03:2021"], [79, 80]),
    "DOM_based_XSS_Prevention": (["A03:2021"], [79]),
    "Input_Validation": (["A03:2021"], [20]),
    "NoSQL_Security": (["A03:2021"], [943, 89]),
    "Prototype_Pollution_Prevention": (["A03:2021"], [1321]),
    "Access_Control": (["A01:2021"], [284, 285, 862, 863]),
    "Authorization": (["A01:2021"], [862, 863, 285]),
    "Insecure_Direct_Object_Reference_Prevention": (["A01:2021"], [639]),
    "Cross-Site_Request_Forgery_Prevention": (["A01:2021"], [352]),
    "Unvalidated_Redirects_and_Forwards": (["A01:2021"], [601]),
    "Mass_Assignment": (["A04:2021", "A08:2021"], [915]),
    "File_Upload": (["A04:2021"], [434]),
    "Error_Handling": (["A04:2021", "A05:2021"], [209, 755]),
    "Business_Logic_Security": (["A04:2021"], [840]),
    "Denial_of_Service": (["A04:2021"], [400, 770]),
    "Cryptographic_Storage": (["A02:2021"], [327, 326, 328, 330, 321]),
    "Key_Management": (["A02:2021"], [321, 320]),
    "Password_Storage": (["A02:2021", "A07:2021"], [916, 759, 760, 327, 328]),
    "Transport_Layer_Security": (["A02:2021"], [319, 326, 327]),
    "Transport_Layer_Protection": (["A02:2021"], [319]),
    "HTTP_Strict_Transport_Security": (["A02:2021", "A05:2021"], [319]),
    "Pinning": (["A02:2021"], [295]),
    "Authentication": (["A07:2021"], [287, 306, 307, 521]),
    "Session_Management": (["A07:2021"], [384, 613, 614]),
    "Forgot_Password": (["A07:2021"], [640]),
    "Multifactor_Authentication": (["A07:2021"], [308, 287]),
    "Credential_Stuffing_Prevention": (["A07:2021"], [307, 521]),
    "Secrets_Management": (["A07:2021", "A02:2021"], [798, 259, 321]),
    "JSON_Web_Token": (["A02:2021", "A07:2021"], [347, 345]),
    "OAuth2": (["A07:2021"], [287]),
    "HTTP_Headers": (["A05:2021"], [693, 1021, 16]),
    "Content_Security_Policy": (["A05:2021", "A03:2021"], [79, 693]),
    "XML_External_Entity_Prevention": (["A05:2021"], [611, 776]),
    "XML_Security": (["A05:2021"], [611]),
    "Docker_Security": (["A05:2021"], [250, 16]),
    "Kubernetes_Security": (["A05:2021"], [16, 250]),
    "Infrastructure_as_Code_Security": (["A05:2021"], [16, 732]),
    "Secure_Cloud_Architecture": (["A05:2021"], [16]),
    "Django_Security": (["A05:2021", "A03:2021"], [79, 352, 16]),
    "Django_REST_Framework": (["A01:2021", "A05:2021"], [862, 16]),
    "Nodejs_Security": (["A05:2021", "A03:2021"], [79, 78, 94]),
    "Java_Security": (["A03:2021", "A08:2021"], [89, 502]),
    "DotNet_Security": (["A05:2021"], [16]),
    "Deserialization": (["A08:2021"], [502]),
    "CI_CD_Security": (["A08:2021"], [829, 494]),
    "GitHub_Actions_Security": (["A08:2021"], [829, 78]),
    "Software_Supply_Chain_Security": (["A06:2021", "A08:2021"], [829, 494, 1104]),
    "Vulnerable_Dependency_Management": (["A06:2021"], [1104, 937]),
    "NPM_Security": (["A06:2021"], [1104, 829]),
    "Dependency_Graph_SBOM": (["A06:2021"], [1104]),
    "Logging": (["A09:2021"], [117, 223, 532, 778]),
    "Logging_Vocabulary": (["A09:2021"], [778]),
    "Server_Side_Request_Forgery_Prevention": (["A10:2021"], [918]),
}  # fmt: skip

MAX_CHUNK = 1400  # characters; sections longer than this are split on paragraph boundaries
MIN_CHUNK = 120


def curl(url: str, dest: Path | None = None) -> bytes:
    cmd = ["curl", "-sSL", "--fail", "-m", "60", "-A", "bulwark-corpus-builder", url]
    out = subprocess.run(cmd, capture_output=True, check=True).stdout
    if dest:
        dest.write_bytes(out)
    return out


def _text(el: ET.Element | None) -> str:
    if el is None:
        return ""
    return re.sub(r"\s+", " ", "".join(el.itertext())).strip()


def build_cwe(wanted: set[int]) -> tuple[list[dict], str]:
    with tempfile.TemporaryDirectory() as tmp:
        zpath = Path(tmp) / "cwe.zip"
        curl(CWE_ZIP, zpath)
        with zipfile.ZipFile(zpath) as z:
            name = next(n for n in z.namelist() if n.endswith(".xml"))
            root = ET.fromstring(z.read(name))
    version = root.attrib.get("Version", "?")
    ns = {"c": root.tag.split("}")[0].strip("{")}
    docs: list[dict] = []
    for w in root.iterfind(".//c:Weakness", ns):
        cid = int(w.attrib["ID"])
        if cid not in wanted:
            continue
        mitigations = []
        for m in w.iterfind("c:Potential_Mitigations/c:Mitigation", ns):
            phase = ", ".join(_text(p) for p in m.iterfind("c:Phase", ns))
            desc = re.sub(r"\s*\[REF-\d+\]", "", _text(m.find("c:Description", ns)))
            if desc:
                mitigations.append(f"[{phase}] {desc}" if phase else desc)
        consequences = []
        for c in w.iterfind("c:Common_Consequences/c:Consequence", ns):
            scopes = ", ".join(_text(s) for s in c.iterfind("c:Scope", ns))
            impacts = ", ".join(_text(s) for s in c.iterfind("c:Impact", ns))
            if scopes or impacts:
                consequences.append(f"{scopes}: {impacts}".strip(": "))
        docs.append(
            {
                "id": f"CWE-{cid}",
                "name": w.attrib.get("Name", ""),
                "abstraction": w.attrib.get("Abstraction", ""),
                "description": _text(w.find("c:Description", ns)),
                "extended": _text(w.find("c:Extended_Description", ns)),
                "consequences": consequences[:6],
                "mitigations": mitigations[:6],
                "url": f"https://cwe.mitre.org/data/definitions/{cid}.html",
            }
        )
    docs.sort(key=lambda d: int(d["id"].split("-")[1]))
    return docs, version


def split_sections(md: str) -> list[tuple[str, str]]:
    """Markdown -> [(heading path, text)]. Code fences are kept whole; front matter and links are cleaned."""
    md = re.sub(r"\A---.*?---\s*", "", md, flags=re.S)
    md = re.sub(r"!\[[^\]]*\]\([^)]*\)", "", md)  # drop images
    md = re.sub(r"\[([^\]]+)\]\((?:[^)]+)\)", r"\1", md)  # [text](url) -> text
    path: list[str] = []
    sections: list[tuple[str, list[str]]] = [("", [])]
    in_fence = False
    for line in md.splitlines():
        if line.strip().startswith("```"):
            in_fence = not in_fence
        m = None if in_fence else re.match(r"^(#{1,4})\s+(.*)$", line)
        if m:
            depth = len(m.group(1))
            path = path[: depth - 1] + [m.group(2).strip()]
            sections.append((" > ".join(path), []))
        else:
            sections[-1][1].append(line)
    return [(h, "\n".join(b).strip()) for h, b in sections if "\n".join(b).strip()]


def chunk(text: str) -> list[str]:
    if len(text) <= MAX_CHUNK:
        return [text]
    out: list[str] = []
    cur = ""
    for para in re.split(r"\n\s*\n", text):
        if cur and len(cur) + len(para) + 2 > MAX_CHUNK:
            out.append(cur)
            cur = ""
        cur = f"{cur}\n\n{para}" if cur else para
        while len(cur) > MAX_CHUNK * 1.5:  # a single huge paragraph or code block
            out.append(cur[:MAX_CHUNK])
            cur = cur[MAX_CHUNK:]
    if cur:
        out.append(cur)
    return out


def build_sheets() -> tuple[list[dict], str]:
    sha = json.loads(curl(CS_COMMIT))["sha"]
    rows: list[dict] = []
    for name, (owasp, cwes) in SHEETS.items():
        md = curl(CS_RAW.format(sha=sha, name=name)).decode("utf-8")
        title = name.replace("_", " ")
        n = 0
        for heading, body in split_sections(md):
            if (
                heading.lower().split(" > ")[-1]
                in {"introduction", "references", "see also", "further reading"}
                and len(body) < 400
            ):
                continue
            for part in chunk(body):
                if len(part.strip()) < MIN_CHUNK:
                    continue
                n += 1
                rows.append(
                    {
                        "id": f"cs:{name}:{n}",
                        "sheet": title,
                        "section": heading or title,
                        "text": part.strip(),
                        "owasp": owasp,
                        "cwes": [f"CWE-{c}" for c in cwes],
                        "url": CS_PAGE.format(name=name),
                    }
                )
    return rows, sha


def main() -> None:
    from core.taxonomy import _load

    wanted = {int(c) for e in _load().values() for c in e["cwes"]} | set(EXTRA_CWES)
    cwe_docs, cwe_version = build_cwe(wanted)
    missing = sorted(wanted - {int(d["id"].split("-")[1]) for d in cwe_docs})
    sheets, sha = build_sheets()
    OUT.mkdir(parents=True, exist_ok=True)
    for fname, rows in (("cwe.jsonl", cwe_docs), ("cheatsheets.jsonl", sheets)):
        (OUT / fname).write_text(
            "".join(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n" for r in rows),
            encoding="utf-8",
        )
    (OUT / "SOURCES.json").write_text(
        json.dumps(
            {
                "cwe": {
                    "url": CWE_ZIP,
                    "version": cwe_version,
                    "documents": len(cwe_docs),
                    "requested": len(wanted),
                    "not_in_catalog_as_weakness": missing,
                },
                "cheat_sheets": {
                    "repo": "https://github.com/OWASP/CheatSheetSeries",
                    "commit": sha,
                    "sheets": len(SHEETS),
                    "chunks": len(sheets),
                },
            },
            indent=2,
        )
        + "\n"
    )
    print(
        f"CWE {cwe_version}: {len(cwe_docs)}/{len(wanted)} documents; not found as Weakness: {missing}"
    )
    print(f"cheat sheets @ {sha[:10]}: {len(SHEETS)} sheets -> {len(sheets)} chunks")


if __name__ == "__main__":
    main()
