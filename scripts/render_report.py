#!/usr/bin/env python3
"""Builds the free static report served at /reports/<slug> (HTML) and /reports/<slug>.md.
Usage: render_report.py [--from SOURCE.md]   (with --from: substitute placeholders and write static/reports/<slug>.md first)
Placeholders become root-relative links, so the report works unchanged on any domain:
  [REPORT_URL]#x -> #x   [REPORT_URL]/llms.txt -> /llms.txt   [DATA_URL] -> /reports/data
Only a small Markdown subset is supported (headings, paragraphs, lists, tables, **bold**, *italic*, `code`,
[links](...), and <a id="..."></a> anchors); every other character is HTML-escaped."""
import html, os, re, sys
R = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SLUG = "state-of-x402-2026-10"; DIR = os.path.join(R, "static", "reports")
def substitute(md):
    md = md.replace("[REPORT_URL]/llms.txt", "/llms.txt").replace("[REPORT_URL]#", "#").replace("[DATA_URL]", "/reports/data")
    if "[REPORT_URL]" in md or "[DATA_URL]" in md: raise SystemExit("unhandled placeholder")
    return md
ANCHOR = re.compile(r'<a id="([a-z0-9-]+)"></a>')
def inline(t):
    out = []; i = 0
    for m in re.finditer(r'<a id="[a-z0-9-]+"></a>|`[^`]+`|\*\*[^*]+\*\*|\*[^*]+\*|\[[^\]]+\]\([^)\s]+\)', t):
        out.append(html.escape(t[i:m.start()], quote=False)); s = m.group(0); i = m.end()
        if s.startswith("<a id="): out.append(s)
        elif s.startswith("`"): out.append("<code>" + html.escape(s[1:-1], quote=False) + "</code>")
        elif s.startswith("**"): out.append("<strong>" + inline(s[2:-2]) + "</strong>")
        elif s.startswith("*"): out.append("<em>" + inline(s[1:-1]) + "</em>")
        else:
            txt, href = re.match(r'\[([^\]]+)\]\(([^)\s]+)\)', s).groups()
            if not re.match(r'^(#|/(?!/)|https://)', href): raise SystemExit("unsafe link: " + href)
            out.append('<a href="' + html.escape(href) + '">' + inline(txt) + "</a>")
    out.append(html.escape(t[i:], quote=False)); return "".join(out)
def slugify(t): return re.sub(r"[^a-z0-9]+", "-", t.lower()).strip("-")
def render(md):
    explicit = set(ANCHOR.findall(md)); lines = md.split("\n"); body = []; title = None; i = 0
    while i < len(lines):
        l = lines[i]
        if not l.strip(): i += 1; continue
        m = re.match(r"^(#{1,3}) (.*)$", l)
        if m:
            n = len(m.group(1)); txt = m.group(2); title = title or txt; sid = slugify(txt)
            idattr = "" if sid in explicit else ' id="%s"' % sid
            body.append("<h%d%s>%s</h%d>" % (n, idattr, inline(txt), n)); i += 1; continue
        if l.startswith("|"):
            rows = []
            while i < len(lines) and lines[i].startswith("|"): rows.append([c.strip() for c in lines[i].strip().strip("|").split("|")]); i += 1
            h, rest = rows[0], [r for r in rows[1:] if not all(re.match(r"^:?-+:?$", c) for c in r)]
            body.append("<table><thead><tr>" + "".join("<th>%s</th>" % inline(c) for c in h) + "</tr></thead><tbody>"
                        + "".join("<tr>" + "".join("<td>%s</td>" % inline(c) for c in r) + "</tr>" for r in rest) + "</tbody></table>"); continue
        if l.startswith("- "):
            items = []
            while i < len(lines) and lines[i].startswith("- "): items.append(lines[i][2:]); i += 1
            body.append("<ul>" + "".join("<li>%s</li>" % inline(x) for x in items) + "</ul>"); continue
        if ANCHOR.fullmatch(l.strip()): body.append(l.strip()); i += 1; continue
        para = []
        while i < len(lines) and lines[i].strip() and not re.match(r"^(#{1,3} |\||- )", lines[i]): para.append(lines[i]); i += 1
        body.append("<p>" + "<br>\n".join(inline(x) for x in para) + "</p>")
    css = ("body{font:16px/1.55 system-ui,sans-serif;max-width:52rem;margin:2rem auto;padding:0 1rem;color:#111}"
           "table{border-collapse:collapse;margin:1rem 0}td,th{border:1px solid #ccc;padding:.3rem .6rem;text-align:left}"
           "code{background:#f3f3f3;padding:0 .2rem}a{color:#0645ad}")
    return ('<!doctype html>\n<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            "<title>%s</title><style>%s</style></head><body>\n%s\n<p><a href=\"/reports/%s.md\">Markdown source</a></p>\n</body></html>\n"
            % (html.escape(re.sub(r"[*`]", "", title or SLUG)), css, "\n".join(body), SLUG))
def main(argv):
    if argv[:1] == ["--from"]:
        open(os.path.join(DIR, SLUG + ".md"), "w", encoding="utf-8").write(substitute(open(argv[1], encoding="utf-8").read()))
    md = open(os.path.join(DIR, SLUG + ".md"), encoding="utf-8").read()
    open(os.path.join(DIR, SLUG + ".html"), "w", encoding="utf-8").write(render(md)); print("ok")
if __name__ == "__main__": main(sys.argv[1:])
