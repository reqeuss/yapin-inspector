#!/usr/bin/env python3
"""Yapin Inspector: collecte HTTP passive et analyse statique locale."""
from __future__ import annotations
import argparse, hashlib, html, json, re, sys, urllib.error, urllib.parse, urllib.request
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path

ALLOWED_HOSTS = {"yapin.gg", "www.yapin.gg"}
TEXT_EXTS = {".html", ".htm", ".js", ".mjs", ".cjs", ".css", ".json", ".map", ".txt", ".xml"}
MAX_FILE = 8 * 1024 * 1024
MAX_TOTAL = 50 * 1024 * 1024
MAX_RESOURCES = 100
RULES = [
    ("secret-like", "Chaîne ressemblant à un secret ou une clé", r"""(?i)(?:api[_-]?key|access[_-]?token|client[_-]?secret|secret[_-]?key)\s*[:=]\s*["'][^"'\r\n]{8,}["']""", "high"),
    ("private-key", "Marqueur de clé privée", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "critical"),
    ("eval", "Utilisation de eval()", r"\beval\s*\(", "medium"),
    ("innerHTML", "Usage de innerHTML", r"\.innerHTML\b", "medium"),
    ("document-write", "Utilisation de document.write()", r"\bdocument\.write\s*\(", "low"),
    ("postmessage", "postMessage avec origine wildcard possible", r"""\.postMessage\s*\([^;]{0,300},\s*['"]\*['"]\s*\)""", "medium"),
]
API_RE = re.compile(r"""(?:(?:https?://[^\s"'<>]+)|(?:/)(?:api|graphql|v[0-9]+)(?:/[A-Za-z0-9_?&=./{}:-]*)?)""", re.I)
LIB_RE = re.compile(r"(?i)(react(?:\.production)?(?:\.min)?\.js|vue(?:\.global)?(?:\.prod)?(?:\.min)?\.js|jquery[-.]?[0-9.]*\.js|angular(?:\.min)?\.js|axios(?:\.min)?\.js)")

class AssetParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.assets = []
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "script" and a.get("src"):
            self.assets.append(a["src"])
        elif tag == "link" and a.get("href"):
            rel = a.get("rel", "").lower().split()
            if "stylesheet" in rel:
                self.assets.append(a["href"])

def safe_url(url: str) -> str:
    p = urllib.parse.urlsplit(url)
    if p.scheme not in ("http", "https") or (p.hostname or "").lower() not in ALLOWED_HOSTS:
        raise ValueError("URL refusée : seules les pages publiques de yapin.gg sont autorisées.")
    if p.username or p.password:
        raise ValueError("Les URL avec identifiants intégrés sont refusées.")
    return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path or "/", p.query, ""))

def request_bytes(url: str):
    req = urllib.request.Request(url, headers={"User-Agent":"YapinInspector/0.2 (passive public asset inventory)", "Accept":"text/html,application/javascript,text/css,*/*;q=0.5"})
    with urllib.request.urlopen(req, timeout=15) as response:
        final = safe_url(response.geturl())
        if response.status != 200:
            raise ValueError(f"Réponse HTTP inattendue : {response.status}")
        data = response.read(MAX_FILE + 1)
        if len(data) > MAX_FILE:
            raise ValueError("Ressource trop volumineuse (limite 8 Mio).")
        return data, response.headers.get_content_type(), final

def local_name(url: str) -> Path:
    p = urllib.parse.urlsplit(url)
    name = p.path.lstrip("/") or "index.html"
    path = Path(name)
    if path.suffix == "":
        path = path / "index.html"
    # Évite les segments de traversée et conserve un chemin relatif sûr.
    parts = [x for x in path.parts if x not in ("..", ".", "/", "\\")]
    out = Path(*parts) if parts else Path("index.html")
    if p.query:
        out = out.with_name(out.stem + "_" + hashlib.sha256(p.query.encode()).hexdigest()[:8] + out.suffix)
    return out

def fetch_site(start: str, output: Path):
    start = safe_url(start)
    queue, seen, total, saved = [start], set(), 0, []
    while queue and len(seen) < MAX_RESOURCES and total < MAX_TOTAL:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        try:
            data, mime, final = request_bytes(url)
        except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
            print(f"[SKIP] {url} — {exc}")
            continue
        if final in {x["url"] for x in saved}:
            continue
        total += len(data)
        rel = local_name(final)
        dest = output / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        saved.append({"url":final, "file":str(rel).replace("\\","/"), "size":len(data),
                      "sha256":hashlib.sha256(data).hexdigest(), "content_type":mime})
        print(f"[OK] {final} -> {rel}")
        text = data.decode("utf-8", errors="replace")
        if mime == "text/html" or rel.suffix.lower() in {".html", ".htm"}:
            parser = AssetParser()
            parser.feed(text)
            for asset in parser.assets:
                candidate = urllib.parse.urljoin(final, asset)
                try:
                    candidate = safe_url(candidate)
                except ValueError:
                    continue
                if candidate not in seen and candidate not in queue:
                    queue.append(candidate)
        elif mime == "text/css" or rel.suffix.lower() == ".css":
            for match in re.finditer(r"""@import\s+(?:url\()?['"]?([^'"\)\s;]+)""", text, re.I):
                candidate = urllib.parse.urljoin(final, match.group(1))
                try:
                    candidate = safe_url(candidate)
                except ValueError:
                    continue
                if candidate not in seen and candidate not in queue:
                    queue.append(candidate)
    output.mkdir(parents=True, exist_ok=True)
    (output/"download-manifest.json").write_text(json.dumps(saved, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nCollecte terminée : {len(saved)} ressources, {total/1024/1024:.2f} Mio.")
    print("Aucune connexion, aucun cookie et aucune requête d'exploitation n'ont été utilisés.")

def analyze(root: Path):
    findings, inventory, endpoints, libraries = [], [], set(), set()
    for path in sorted(p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in TEXT_EXTS):
        try:
            raw = path.read_bytes()
            if len(raw) > MAX_FILE:
                inventory.append({"file":str(path.relative_to(root)), "size":len(raw), "skipped":"plus de 8 Mio"})
                continue
            source = raw.decode("utf-8", errors="replace")
        except OSError:
            continue
        rel = str(path.relative_to(root)).replace("\\","/")
        inventory.append({"file":rel, "size":len(raw), "sha256":hashlib.sha256(raw).hexdigest()})
        for kind, title, pattern, severity in RULES:
            for match in re.finditer(pattern, source):
                evidence = "[CONTENU MASQUÉ — vérifier localement]" if kind in ("secret-like","private-key") else source[max(0,match.start()-45):match.end()+45]
                findings.append({"type":kind,"title":title,"severity":severity,"file":rel,
                    "line":source.count("\n",0,match.start())+1,"evidence":evidence})
        endpoints.update(m.group(0)[:250] for m in API_RE.finditer(source))
        libraries.update(m.group(0) for m in LIB_RE.finditer(source))
    return findings, inventory, sorted(endpoints), sorted(libraries)

def write_report(out: Path, root: Path, findings, inventory, endpoints, libraries):
    out.mkdir(parents=True, exist_ok=True)
    data = {"tool":"Yapin Inspector","generated_at":datetime.now(timezone.utc).isoformat(),
        "scope":str(root.resolve()),"note":"Analyse statique indicative, sans validation active.",
        "findings":findings,"inventory":inventory,"endpoints":endpoints,"libraries":libraries}
    (out/"report.json").write_text(json.dumps(data,indent=2,ensure_ascii=False),encoding="utf-8")
    (out/"inventory.json").write_text(json.dumps(inventory,indent=2,ensure_ascii=False),encoding="utf-8")
    rows = "".join("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>".format(
        html.escape(x["severity"]),html.escape(x["title"]),html.escape(x["file"]),x["line"],html.escape(x["evidence"])) for x in findings)
    def items(values):
        return "".join("<li><code>"+html.escape(str(v))+"</code></li>" for v in values)
    # Remplacement de marqueurs au lieu de str.format : les accolades du CSS ne sont pas interprétées.
    page = """<!doctype html><html lang="fr"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Yapin Inspector</title><style>
body{font:15px system-ui;background:#0b0d10;color:#e8edf2;margin:0;padding:30px}
main{max-width:1100px;margin:auto}p{color:#aab4c0}.panel{background:#151a20;border:1px solid #29313b;border-radius:12px;padding:18px;margin:18px 0}
table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:9px;border-bottom:1px solid #303943;vertical-align:top}
th{color:#aab4c0}code{overflow-wrap:anywhere;color:#b9ff5c}.accent{color:#b9ff5c}
</style><main><h1>YAPIN <span class="accent">INSPECTOR</span></h1>
<p>Analyse statique locale · Les alertes sont des pistes à vérifier.</p>
<div class="panel"><h2>Résumé</h2><p>__FILES__ fichiers · __FINDINGS__ alertes · __URLS__ URL/chemins</p></div>
<div class="panel"><h2>Alertes</h2><table><tr><th>Niveau</th><th>Détection</th><th>Fichier</th><th>Ligne</th><th>Contexte</th></tr>__ROWS__</table></div>
<div class="panel"><h2>URL et routes repérées</h2><ul>__ENDPOINTS__</ul></div>
<div class="panel"><h2>Bibliothèques repérées</h2><ul>__LIBS__</ul></div>
<div class="panel"><h2>Inventaire</h2><ul>__INVENTORY__</ul></div>
<p>Ne partage pas de secrets, jetons ou données personnelles découverts pendant l'audit.</p></main></html>"""
    replacements = {"__FILES__":str(len(inventory)),"__FINDINGS__":str(len(findings)),
        "__URLS__":str(len(endpoints)),"__ROWS__":rows,"__ENDPOINTS__":items(endpoints),
        "__LIBS__":items(libraries),"__INVENTORY__":items([f'{x["file"]} — {x["size"]} octets' for x in inventory])}
    for key,value in replacements.items():
        page = page.replace(key,value)
    (out/"report.html").write_text(page,encoding="utf-8")

def compare(old: Path, new: Path):
    for p in (old,new):
        if not p.is_file():
            raise FileNotFoundError(f"Inventaire introuvable : {p}")
    a = {x["file"]:x.get("sha256") for x in json.loads(old.read_text(encoding="utf-8"))}
    b = {x["file"]:x.get("sha256") for x in json.loads(new.read_text(encoding="utf-8"))}
    print("Nouveaux :", *sorted(b.keys()-a.keys()), sep="\n  ")
    print("Supprimés :", *sorted(a.keys()-b.keys()), sep="\n  ")
    print("Modifiés :", *sorted(k for k in a.keys() & b.keys() if a[k]!=b[k]), sep="\n  ")

def main():
    parser=argparse.ArgumentParser(description="Analyseur passif des ressources web publiques de Yapin.")
    sub=parser.add_subparsers(dest="cmd",required=True)
    f=sub.add_parser("fetch",help="Télécharger la page publique et ses scripts/CSS same-origin")
    f.add_argument("url",nargs="?",default="https://yapin.gg/")
    f.add_argument("--output",type=Path,default=Path("yapin-files"))
    s=sub.add_parser("scan",help="Analyser un dossier local")
    s.add_argument("directory",type=Path); s.add_argument("--output",type=Path,default=Path("rapport"))
    c=sub.add_parser("compare",help="Comparer deux inventaires")
    c.add_argument("old",type=Path); c.add_argument("new",type=Path)
    args=parser.parse_args()
    try:
        if args.cmd=="fetch":
            fetch_site(args.url,args.output)
        elif args.cmd=="scan":
            if not args.directory.is_dir(): parser.error(f"Le dossier n'existe pas : {args.directory}")
            result=analyze(args.directory); write_report(args.output,args.directory,*result)
            print(f"Terminé : {len(result[1])} fichiers, {len(result[0])} alertes.")
            print("Rapport :",args.output/"report.html")
        else: compare(args.old,args.new)
    except (OSError,ValueError,urllib.error.URLError) as exc:
        print(f"Erreur : {exc}",file=sys.stderr); return 1
    return 0
if __name__=="__main__":
    raise SystemExit(main())
