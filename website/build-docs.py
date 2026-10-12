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
    ('quickstart-account', 'Quickstart: Account', 'Your wallet. Your programmable keys.'),
    ('quickstart-program', 'Quickstart: Program', 'Your program. Your signing rules.'),
    ('quickstart-passkey', 'Quickstart: Passkey', 'Quickstart: Passkey'),
    ('quickstart-oidc', 'Quickstart: OAuth/OIDC', 'Quickstart: OAuth/OIDC'),
    ('demo', 'Interactive demo', 'See the rules in action.'),
    ('architecture', 'Architecture', 'One authority. Two signers.'),
    ('integration', 'Solana program integration', 'Make your program the authority.'),
    ('policy', 'Policy & rules', 'Make permission programmable.'),
    ('sessions', 'Scoped sessions', 'Delegate within your rules.'),
    ('signing', 'Signing schemes', 'Signing schemes'),
    ('api', 'SDK & API reference', 'Request, verify, and deliver.'),
    ('security', 'Security & status', 'Understand the trust model.'),
    ('local-development', 'Local development', 'Run your own development stack.'),
    ('testnet', 'Operator testnet setup', 'From Solana authority to Base execution.'),
]
ALIASES = {'quickstart':'quickstart', 'integration':'integration', 'sessions':'sessions',
           'jobs':'api', 'status':'security', 'sources':'security'}

def url(slug):
    return 'docs.html' if slug == 'overview' else f'docs/{slug}.html'

def render(index):
    slug, label, title = PAGES[index]
    prefix = '' if slug == 'overview' else '../'
    body = (ROOT / 'content' / f'{slug}.html').read_text()
    body = body.replace('<!-- HOSTED_CONTROLLER_SOURCE -->', '<pre><code class="language-rust">' + html.escape((ROOT.parent / 'programs/example-controller/src/approval.rs').read_text()) + '</code></pre>')
    for anchor, target in ALIASES.items():
        body = body.replace(f'docs.html#{anchor}', f'{url(target)}#{anchor}')
    # Content links are repository-site-root relative; resolve them for each output page.
    body = re.sub(r'href="(?!https?://|#|/)([^"]+)"', lambda m: f'href="{prefix}{m[1]}"', body)
    links = '\n'.join(f'<a href="{prefix}{url(key)}"' + (' aria-current="page"' if key == slug else '') + f'>{html.escape(name)}</a>' for key,name,_ in PAGES)
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
<link rel="stylesheet" href="{prefix}style.css?v=gold-1"><script src="{prefix}docs.js" defer></script></head>
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
    outputs[ROOT / 'examples/hosted-client-v2.zip'] = archive_files({name: (ROOT / name).read_bytes() for name in ['hosted-v2.mjs', 'hosted-client.mjs', 'approval-codec.mjs']})
    for path,data in outputs.items():
        if args.check:
            if not path.exists() or path.read_bytes()!=data:
                raise SystemExit(f'Stale generated file: {path.relative_to(ROOT)}; run python3 website/build-docs.py')
        else:
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(data)
    print(f'{"Checked" if args.check else "Generated"} {len(PAGES)} docs pages and downloadable examples.')
if __name__=='__main__':main()
