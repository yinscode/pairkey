#!/usr/bin/env python3
"""Generate the buildless docs from HTML fragments; --check detects stale output."""
from pathlib import Path
import argparse
import html
import re
import io
import zipfile

ROOT = Path(__file__).resolve().parent
PAGES = [
    ('overview', 'Overview', 'Build with programmable keys.'),
    ('quickstart', 'Quickstart', 'Build with hosted signers.'),
    ('keys-and-namespaces', 'Keys & namespaces', 'Choose stable key identities for each purpose.'),
    ('quickstart-account', 'Quickstart: Account', 'Your wallet. Your programmable keys.'),
    ('quickstart-program', 'Quickstart: Program', 'Your program. Your signing rules.'),
    ('quickstart-passkey', 'Quickstart: Passkey', 'Quickstart: Passkey'),
    ('quickstart-oidc', 'Quickstart: OIDC/OAuth', 'Quickstart: OIDC/OAuth'),
    ('demo', 'Interactive demo', 'See the rules in action.'),
    ('architecture', 'Architecture', 'One authority. Two signers.'),
    ('supported-chains', 'Supported chains', 'Supported chains'),
    ('tutorial-program-keys', 'Tutorial: Program keys', 'Three ways to use program-controlled keys.'),
    ('tutorial-hyperliquid', 'Tutorial: Hyperliquid', 'Solana assets and Hyperliquid signing.'),
    ('tutorial-aave', 'Tutorial: Aave lending', 'Use a program-controlled key with Aave.'),
    ('tutorial-zcash-escrow', 'Tutorial: Zcash escrow', 'Design a shielded Zcash escrow.'),
    ('tutorial-btcfi', 'Tutorial: BTCFi', 'Design Taproot signing for BTCFi.'),
    ('integration', 'Solana program integration', 'Make your program the authority.'),
    ('signing', 'Signing schemes', 'Signing schemes'),
    ('policy', 'Policy & rules', 'Make permission programmable.'),
    ('policy-demo', 'Policy demo', 'See program approval rules in action.'),
    ('api', 'SDK & API reference', 'Request, verify, and deliver.'),
    ('security', 'Security & status', 'Understand the trust model.'),
    ('sessions', 'Scoped sessions', 'Delegate within your rules.'),
    ('local-development', 'Local development', 'Run your own development stack.'),
    ('testnet', 'Operator testnet setup', 'From Solana authority to Base execution.'),
]
NAV_GROUPS = [
    ('Getting started', ['quickstart', 'keys-and-namespaces', 'quickstart-account',
                         'quickstart-program', 'quickstart-passkey', 'quickstart-oidc', 'demo']),
    ('Tutorials', ['tutorial-program-keys', 'tutorial-hyperliquid', 'tutorial-aave',
                   'tutorial-zcash-escrow', 'tutorial-btcfi']),
    ('Concepts', ['architecture', 'supported-chains', 'integration', 'signing',
                  'policy', 'policy-demo', 'sessions']),
    ('Reference', ['api', 'security', 'local-development', 'testnet']),
]
assert sorted(key for _, keys in NAV_GROUPS for key in keys) == sorted(
    key for key, _, _ in PAGES if key != 'overview')
ALIASES = {'quickstart':'quickstart', 'integration':'integration', 'sessions':'sessions',
           'jobs':'api', 'status':'security', 'sources':'security'}

def url(slug):
    return 'docs.html' if slug == 'overview' else f'docs/{slug}.html'

def nav_links(slug, prefix):
    names = {key: name for key, name, _ in PAGES}
    def link(key):
        current = ' aria-current="page"' if key == slug else ''
        return f'<a href="{prefix}{url(key)}"{current}>{html.escape(names[key])}</a>'
    groups = [link('overview')]
    for title, keys in NAV_GROUPS:
        expanded = ' open' if slug in keys or (slug == 'overview' and title == 'Getting started') else ''
        items = '\n'.join(link(key) for key in keys)
        groups.append(f'<details{expanded}><summary>{html.escape(title)}</summary>'
                      f'<div class="docs-nav-group-links">{items}</div></details>')
    return '\n'.join(groups)

def render(index):
    slug, label, title = PAGES[index]
    prefix = '' if slug == 'overview' else '../'
    body = (ROOT / 'content' / f'{slug}.html').read_text()
    body = body.replace('<!-- HOSTED_CONTROLLER_SOURCE -->', '<pre><code class="language-rust">' + html.escape((ROOT.parent / 'programs/example-controller/src/approval.rs').read_text()) + '</code></pre>')
    for anchor, target in ALIASES.items():
        body = body.replace(f'docs.html#{anchor}', f'{url(target)}#{anchor}')
    # Content links are repository-site-root relative; resolve them for each output page.
    body = re.sub(r'href="(?!https?://|#|/)([^"]+)"', lambda m: f'href="{prefix}{m[1]}"', body)
    links = nav_links(slug, prefix)
    headings = re.findall(r'<h2 id="([^"]+)">(.*?)</h2>', body)
    toc = ''.join(f'<a href="#{anchor}">{re.sub("<[^>]+>", "", heading)}</a>' for anchor,heading in headings)
    adjacent=[]
    for offset, caption in [(-1, 'Previous'), (1, 'Next')]:
        n=index+offset
        if 0 <= n < len(PAGES):
            key,name,_=PAGES[n]
            adjacent.append(f'<a href="{prefix}{url(key)}"><span>{caption}</span><strong>{html.escape(name)} →</strong></a>')
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="description" content="{html.escape(title)} PairKey developer documentation: {html.escape(label)}.">
<title>{html.escape(label)} — PairKey docs</title><link rel="icon" href="{prefix}mark.svg?v=3" type="image/svg+xml">
<link rel="stylesheet" href="{prefix}style.css?v=docs-nav-2"><script src="{prefix}docs.js?v=docs-nav-2" defer></script></head>
<body><a class="skip" href="#main">Skip to content</a>
<header class="nav wrap"><a class="brand" href="{prefix}index.html"><img src="{prefix}mark.svg?v=3" width="30" height="30" alt="">PairKey</a>
<nav aria-label="Main navigation"><a href="/demo">Demo</a><a href="{prefix}index.html#protocol">Protocol</a><a href="{prefix}docs.html" aria-current="true">Docs</a></nav>
<a class="button small" href="{prefix}docs/quickstart.html">Get started →</a></header>
<div class="wrap docs-layout"><aside class="docs-sidebar"><p class="eyebrow">BUILD WITH PAIRKEY</p><nav class="docs-nav" aria-label="Documentation">{links}</nav></aside>
<main id="main" class="docs-content"><p class="eyebrow"><a href="{prefix}docs.html">DOCS</a> / {html.escape(label.upper())}</p>
<h1{' id="overview"' if slug == 'overview' else ''}>{html.escape(title)}</h1><nav class="docs-toc" aria-label="On this page"><strong>On this page</strong>{toc}</nav>
{body}
<nav class="docs-pagination" aria-label="Next and previous pages">{''.join(adjacent)}</nav></main></div>
<footer class="wrap footer"><a class="brand" href="{prefix}index.html"><img src="{prefix}mark.svg?v=3" width="26" height="26" alt="">PairKey</a><p>Programmable keys on multiple chains</p><a href="{prefix}docs/security.html">Security &amp; status →</a></footer></body></html>
'''

def archive_files(files):
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as bundle:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            bundle.writestr(info, data)
    return archive.getvalue()

def controller_bundle():
    repo = ROOT.parent
    template = repo / 'examples/hosted-controller'
    manifest = (template / 'Cargo.toml').read_text().replace('../../programs/example-controller', 'vendor/programs/example-controller')
    # The bundled path dependencies inherit the exact repository versions.
    manifest += '\n[workspace.package]' + (repo / 'Cargo.toml').read_text().split('[workspace.package]', 1)[1]
    files = {'Cargo.toml': manifest.encode(), 'Cargo.lock': (template / 'Cargo.lock').read_bytes(), 'src/lib.rs': (template / 'src/lib.rs').read_bytes(), 'README.md': (template / 'README.md').read_bytes()}
    for crate in ['programs/example-controller', 'programs/pair-registry', 'crates/pairkey-types']:
        base = repo / crate
        for path in [base / 'Cargo.toml', *sorted(base.rglob('*.rs'))]:
            data = path.read_bytes()
            if path.name == 'Cargo.toml':
                # Dependency tests are maintained in the repository, not in the
                # standalone app download. Exclude their unrelated path crates.
                data = data.decode().split('[dev-dependencies]', 1)[0].encode()
            files['vendor/' + path.relative_to(repo).as_posix()] = data
    files['vendor/programs/program-id-build.rs'] = (repo / 'programs/program-id-build.rs').read_bytes()
    return archive_files({'hosted-controller/' + name: data for name, data in files.items()})

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args=parser.parse_args()
    outputs={ROOT / url(slug):render(i).encode() for i,(slug,_,_) in enumerate(PAGES)}
    outputs[ROOT / 'examples/program_jobs.rs']=(ROOT.parent / 'sdk/examples/program_jobs.rs').read_bytes()
    outputs[ROOT / 'examples/verify_hosted.rs']=(ROOT.parent / 'sdk/examples/verify_hosted.rs').read_bytes()
    outputs[ROOT / 'examples/hosted-controller.rs']=(ROOT.parent / 'examples/hosted-controller/src/lib.rs').read_bytes()
    outputs[ROOT / 'examples/program-approval.rs']=(ROOT.parent / 'programs/example-controller/src/approval.rs').read_bytes()
    outputs[ROOT / 'examples/hosted-controller.zip'] = controller_bundle()
    outputs[ROOT / 'examples/hosted-client-v2.zip'] = archive_files({name: (ROOT / name).read_bytes() for name in ['pairkey-client.mjs', 'pairkey-client.d.ts', 'program-client.mjs', 'program-client.d.ts', 'hosted-session.mjs', 'hosted-v2.mjs', 'hosted-client.mjs', 'approval-codec.mjs', 'package.json', 'PACKAGE-README.md']})
    for path,data in outputs.items():
        if args.check:
            if not path.exists() or path.read_bytes()!=data:
                raise SystemExit(f'Stale generated file: {path.relative_to(ROOT)}; run python3 website/build-docs.py')
        else:
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(data)
    print(f'{"Checked" if args.check else "Generated"} {len(PAGES)} docs pages and downloadable examples.')
if __name__=='__main__':main()
