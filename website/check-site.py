#!/usr/bin/env python3
"""Check generated docs and every local link/fragment/asset on the public pages."""
from pathlib import Path
from html.parser import HTMLParser
from urllib.parse import urlsplit, unquote
import subprocess
import sys
ROOT=Path(__file__).resolve().parent
class Page(HTMLParser):
    def __init__(self):
        super().__init__(); self.ids=[]; self.links=[]; self.headings=0; self.labels=[]
    def handle_starttag(self, tag, attrs):
        a=dict(attrs)
        if 'id' in a: self.ids.append(a['id'])
        if tag=='h1': self.headings+=1
        if tag=='label' and 'for' in a:self.labels.append(a['for'])
        for key in ('href','src'):
            if key in a:self.links.append(a[key])
subprocess.run([sys.executable,str(ROOT/'build-docs.py'),'--check'],check=True)
pages={}
for path in [ROOT/'index.html',ROOT/'demo.html',ROOT/'docs.html',*sorted((ROOT/'docs').glob('*.html'))]:
    page=Page();page.feed(path.read_text());pages[path.resolve()]=page
    assert len(page.ids)==len(set(page.ids)),f'Duplicate ID: {path}'
    assert page.headings==1,f'Expected one h1: {path}'
    assert all(label in page.ids for label in page.labels),f'Missing form control: {path}'
for path,page in pages.items():
    for link in page.links:
        u=urlsplit(link)
        if u.scheme or u.netloc:continue
        site_path = unquote(u.path)
        route = {'/': 'index.html', '/demo': 'demo.html', '/demo/': 'demo.html', '/testnet.html': 'demo.html'}
        target = (ROOT/route[site_path]).resolve() if site_path in route else ((ROOT/site_path.lstrip('/')).resolve() if site_path.startswith('/') else (path.parent/site_path).resolve() if site_path else path)
        assert target.is_relative_to(ROOT),f'Link escapes website: {path}: {link}'
        assert target.is_file(),f'Missing asset: {path}: {link}'
        if u.fragment:assert target in pages and u.fragment in pages[target].ids,f'Missing fragment: {path}: {link}'
print(f'Checked {len(pages)} public pages: links, fragments, assets, labels, and headings.')
