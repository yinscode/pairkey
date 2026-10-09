#!/usr/bin/env python3
"""Build the exact downloadable application bundle in isolation, optionally as SBF."""
from pathlib import Path
import argparse
import os
import shutil
import subprocess
import tempfile
import zipfile

root = Path(__file__).resolve().parent.parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--sbf', action='store_true')
args = parser.parse_args()
with tempfile.TemporaryDirectory(prefix='pairkey-controller-download-') as directory:
    with zipfile.ZipFile(root / 'website/examples/hosted-controller.zip') as bundle:
        for name in bundle.namelist():
            assert not Path(name).is_absolute() and '..' not in Path(name).parts
        bundle.extractall(directory)
    manifest = Path(directory) / 'hosted-controller/Cargo.toml'
    target = root / 'target/hosted-controller-bundle'
    env = os.environ.copy()
    if args.sbf:
        env['RUSTC'] = env['PAIRKEY_SBF_RUSTC']
        output = target / 'deploy'
        subprocess.run(['cargo', 'build-sbf', '--manifest-path', str(manifest),
                        '--sbf-sdk', env['PAIRKEY_SBF_SDK'], '--tools-version', 'v1.56',
                        '--skip-tools-install', '--no-rustup-override',
                        '--sbf-out-dir', str(output), '--', '--locked',
                        '--target-dir', str(target / 'sbf')], env=env, check=True)
        shutil.copy2(output / 'pairkey_hosted_controller_example.so', output / 'example_controller.so')
        shutil.copy2(root / 'target/deploy/pair_registry.so', output / 'pair_registry.so')
        env.pop('RUSTC')
        env['PAIRKEY_PROGRAM_DIR'] = str(output)
        subprocess.run(['cargo', 'test', '-p', 'pairkey-platform-tests', '--test',
                        'program_approval', '--locked', '--', '--ignored'], cwd=root, env=env, check=True)
    else:
        subprocess.run(['cargo', 'check', '--manifest-path', str(manifest), '--locked',
                        '--target-dir', str(target)], env=env, check=True)
print('Downloaded controller bundle verified independently of repository path dependencies.')
