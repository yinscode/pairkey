#!/usr/bin/env python3
"""Generate the buildless docs from HTML fragments; --check detects stale output."""
from pathlib import Path
import argparse
import html
import re

ROOT = Path(__file__).resolve().parent
PAGES = [
    ('overview', 'Overview', 'Build with programmable keys.'),
    ('quickstart', 'Quickstart', 'Your first local signing flow.'),
    ('demo', 'Interactive demo', 'See the rules in action.'),
    ('architecture', 'Architecture', 'One authority. Two signers.'),
    ('integration', 'Solana program integration', 'Make your program the authority.'),
    ('sessions', 'Scoped sessions', 'Delegate within your rules.'),
    ('signing', 'Signing integrations', 'One protocol. Multiple destinations.'),
    ('api', 'SDK & API reference', 'Request, verify, and deliver.'),
    ('security', 'Security & status', 'Understand the trust model.'),
]
ALIASES = {'quickstart':'quickstart', 'integration':'integration', 'sessions':'sessions',
           'jobs':'api', 'status':'security', 'sources':'security'}

def url(slug):
    return 'docs.html' if slug == 'overview' else f'docs/{slug}.html'

def render(index):
    slug, label, title = PAGES[index]
    prefix = '' if slug == 'overview' else '../'
    body = (ROOT / 'content' / f'{slug}.html').read_text()
    for anchor, target in ALIASES.items():
        body = body.replace(f'docs.html#{anchor}', f'{url(target)}#{anchor}')
    # Content links are repository-site-root relative; resolve them for each output page.
    body = re.sub(r'href="(?!https?://|#)([^"]+)"', lambda m: f'href="{prefix}{m[1]}"', body)
    links = '\n'.join(f'<a href="{prefix}{url(key)}"' + (' aria-current="page"' if key == slug else '') + f'>{html.escape(name)}</a>' for key,name,_ in PAGES)
    headings = re.findall(r'<h2 id="([^"]+)">(.*?)</h2>', body)
    toc = ''.join(f'<a href="#{anchor}">{re.sub("<[^>]+>", "", heading)}</a>' for anchor,heading in headings)
    adjacent=[]
    for offset, caption in [(-1, 'Previous'), (1, 'Next')]:
        n=index+offset
        if 0 <= n < len(PAGES):
            key,name,_=PAGES[n]
            adjacent.append(f'<a href="{prefix}{url(key)}"><span>{caption}</span><strong>{html.escape(name)} ↗</strong></a>')
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="description" content="{html.escape(title)} PairKey developer documentation: {html.escape(label)}.">
<title>{html.escape(label)} — PairKey docs</title><link rel="icon" href="{prefix}mark.svg" type="image/svg+xml">
<link rel="stylesheet" href="{prefix}style.css"><script src="{prefix}docs.js" defer></script></head>
<body><a class="skip" href="#main">Skip to content</a>
<header class="nav wrap"><a class="brand" href="{prefix}index.html"><img src="{prefix}mark.svg" width="30" height="30" alt="">PairKey</a>
<nav aria-label="Main navigation"><a href="{prefix}index.html#demo">Demo</a><a href="{prefix}index.html#protocol">Protocol</a><a href="{prefix}docs.html" aria-current="true">Docs</a></nav>
<a class="button small" href="{prefix}docs/quickstart.html">Run locally ↗</a></header>
<div class="wrap docs-layout"><aside class="docs-sidebar"><p class="eyebrow">BUILD WITH PAIRKEY</p><nav class="docs-nav" aria-label="Documentation">{links}</nav></aside>
<main id="main" class="docs-content"><p class="eyebrow"><a href="{prefix}docs.html">DOCS</a> / {html.escape(label.upper())}</p>
<h1{' id="overview"' if slug == 'overview' else ''}>{html.escape(title)}</h1><nav class="docs-toc" aria-label="On this page"><strong>On this page</strong>{toc}</nav>
{body}
<nav class="docs-pagination" aria-label="Next and previous pages">{''.join(adjacent)}</nav></main></div>
<footer class="wrap footer"><a class="brand" href="{prefix}index.html"><img src="{prefix}mark.svg" width="26" height="26" alt="">PairKey</a><p>Programmable keys. Governed on Solana.</p><a href="{prefix}docs/security.html">Security &amp; status ↗</a></footer></body></html>
'''

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args=parser.parse_args()
    outputs={ROOT / url(slug):render(i).encode() for i,(slug,_,_) in enumerate(PAGES)}
    outputs[ROOT / 'examples/program_jobs.rs']=(ROOT.parent / 'sdk/examples/program_jobs.rs').read_bytes()
    for path,data in outputs.items():
        if args.check:
            if not path.exists() or path.read_bytes()!=data:
                raise SystemExit(f'Stale generated file: {path.relative_to(ROOT)}; run python3 website/build-docs.py')
        else:
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(data)
    print(f'{"Checked" if args.check else "Generated"} {len(PAGES)} docs pages and the Rust example.')
if __name__=='__main__':main()
