#!/usr/bin/env python3
"""Install checksum-pinned tools under ignored .local; never change rustup aliases."""
import hashlib
from pathlib import Path
import platform
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / '.local/ci-tools'
PLATFORM = (platform.system(), platform.machine())
ASSETS = {
    ('Linux', 'x86_64'): [
        ('sbf', 'platform-tools-v1.56', 'anza-xyz/platform-tools', 'v1.56', 'platform-tools-linux-x86_64.tar.bz2', 'afdad6e0672942b00d69fc51ebde0d182c9b9ed21e078357fcedb50f921dae2d'),
        ('agave', 'agave-v3.0.14', 'anza-xyz/agave', 'v3.0.14', 'solana-release-x86_64-unknown-linux-gnu.tar.bz2', '65614325423316a48f57f1ceeaa91ca78f4516e165e305b38c01873cf8c6b8b4'),
        ('foundry', 'foundry-v1.3.1', 'foundry-rs/foundry', 'v1.3.1', 'foundry_v1.3.1_linux_amd64.tar.gz', 'baad3e1b06d6f310d210c93e95258a03d923fe610f8d0742138f2245f94abd7c'),
    ],
    ('Darwin', 'arm64'): [
        ('sbf', 'platform-tools-v1.56', 'anza-xyz/platform-tools', 'v1.56', 'platform-tools-osx-aarch64.tar.bz2', '57cc5b6e7690cdff66fe9aae8f54a2bc2283fa766c207ddfb2cde1c2dd415eeb'),
        ('agave', 'agave-v3.0.14', 'anza-xyz/agave', 'v3.0.14', 'solana-release-aarch64-apple-darwin.tar.bz2', 'cabd08fa7f704d29f8ace6694e06feacffbd5faeb9126fc814af54493371a877'),
        ('foundry', 'foundry-v1.3.1', 'foundry-rs/foundry', 'v1.3.1', 'foundry_v1.3.1_darwin_arm64.tar.gz', 'e3c880d28eae2a150f3f01a674b3cd6a130d6d3f16685740cd1e16538b58a4a5'),
    ],
}

def install(asset):
    kind, directory, repo, version, name, digest = asset
    dest = TOOLS / directory
    marker = dest / '.verified-archive-sha256'
    if marker.exists() and marker.read_text().strip() == digest:
        return
    downloads = TOOLS / 'downloads'
    downloads.mkdir(parents=True, exist_ok=True)
    archive = downloads / name
    if not archive.exists():
        partial = archive.with_suffix(archive.suffix + '.partial')
        subprocess.run(['curl', '--fail', '--location', '--silent', '--show-error', '--retry', '3',
                        f'https://github.com/{repo}/releases/download/{version}/{name}', '-o', str(partial)], check=True)
        partial.rename(archive)
    with archive.open('rb') as stream:
        actual = hashlib.file_digest(stream, 'sha256').hexdigest()
    if actual != digest:
        raise SystemExit(f'Checksum mismatch: {archive}; remove the invalid archive before retrying')
    with tempfile.TemporaryDirectory(dir=TOOLS, prefix='extract-') as tmp:
        with tarfile.open(archive) as bundle:
            bundle.extractall(tmp, filter='data')
        if dest.exists():
            raise SystemExit(f'Unverified tool directory exists: {dest}; preserve/remove it before retrying')
        Path(tmp).rename(dest)
        marker.write_text(digest + '\n')
    print(f'Installed {kind} {version}: {dest}', file=sys.stderr)

def main():
    if sys.version_info < (3, 12):
        raise SystemExit("Python 3.12+ is required for safe archive extraction")
    if PLATFORM not in ASSETS:
        raise SystemExit(f'Unsupported platform {PLATFORM}; supported: Linux x86_64, macOS arm64')
    TOOLS.mkdir(parents=True, exist_ok=True)
    for asset in ASSETS[PLATFORM]:
        install(asset)
    agave = TOOLS / 'agave-v3.0.14/solana-release/bin'
    # Copy only SDK support files; link the verified compiler instead of ~/.cache or rustup aliases.
    sdk = TOOLS / 'sbf-sdk-v1.56'
    if not sdk.exists():
        shutil.copytree(agave / 'platform-tools-sdk/sbf', sdk, ignore=shutil.ignore_patterns('platform-tools'))
    (sdk / 'dependencies').mkdir(exist_ok=True)
    link = sdk / 'dependencies/platform-tools'
    if link.is_symlink():
        link.unlink()
    if link.exists():
        raise SystemExit(f'Expected a managed toolchain symlink: {link}')
    link.symlink_to(TOOLS / 'platform-tools-v1.56', target_is_directory=True)
    # strip.sh sources env.sh, which otherwise invokes the SDK's older installer
    # even with cargo-build-sbf --skip-tools-install. Keep this copied SDK offline.
    installer = sdk / 'scripts/install.sh'
    installer.write_text('#!/usr/bin/env bash\nset -euo pipefail\ntest -x "$(dirname "$0")/../dependencies/platform-tools/llvm/bin/llvm-objcopy"\n')
    installer.chmod(0o755)
    with (TOOLS / 'env.sh').open('w') as out:
        out.write('export PATH=' + shlex.quote(f'{agave}:{TOOLS / "foundry-v1.3.1"}') + ':"$PATH"\n')
        out.write('export PAIRKEY_SBF_RUSTC=' + shlex.quote(str(TOOLS / 'platform-tools-v1.56/rust/bin/rustc')) + '\n')
        out.write('export PAIRKEY_SBF_SDK=' + shlex.quote(str(sdk)) + '\n')
    print(f'Source {TOOLS / "env.sh"} before running scripts/ci.sh', file=sys.stderr)

if __name__ == '__main__':
    main()
