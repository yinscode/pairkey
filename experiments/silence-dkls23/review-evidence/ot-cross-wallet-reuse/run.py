#!/usr/bin/env python3
"""Offline, disposable-source probe. Writes no key material to disk."""
from pathlib import Path
import hashlib, shutil, subprocess, tarfile, tempfile
here = Path(__file__).resolve().parent
root = here.parents[3]
rev = 'af5ada2a2e573c2c8eac5b01f9bbc4bf1c331ac7'
archive = root / '.local/silence-dkls23/sources/dkls23.tar.gz'
assert hashlib.sha256(archive.read_bytes()).hexdigest() == 'e7301fa0886c0232cdf7dad7b2827ef0ce0ea84c1853ea926fe781865d320c9b'
scratch = Path(tempfile.mkdtemp(prefix='pairkey-ot-reuse-',dir='/tmp'))
with tarfile.open(archive) as t:
    t.extractall(scratch,filter='data')
native = scratch / ('dkls23-' + rev)
keyshare = native / 'src/keygen/keyshare.rs'
keyshare.write_text(keyshare.read_text() + '\n' + (here/'keyshare_test_access.rs').read_text())
probe = scratch/'probe'
(probe/'src').mkdir(parents=True)
shutil.copyfile(here/'main.rs',probe/'src/main.rs')
shutil.copyfile(here/'Cargo.lock.used',probe/'Cargo.lock')
(probe/'Cargo.toml').write_text(f'''[package]
name="ot-cross-wallet-reuse-probe"
version="0.1.0"
edition="2021"
[workspace]
[dependencies]
sl-dkls23={{path="../dkls23-{rev}",default-features=false,features=["test-support","multi-thread"]}}
sl-mpc-mate={{version="=1.0.0-beta",features=["simple-relay"]}}
sl-oblivious="=1.0.0-beta"
k256={{version="=0.13.4",features=["ecdsa"]}}
tokio={{version="=1.48.0",features=["macros","rt-multi-thread","time"]}}
rand_core={{version="=0.6.4",features=["getrandom"]}}
derivation-path="=0.2.0"
bytemuck={{version="=1.25.0",features=["extern_crate_alloc","min_const_generics"]}}
''')
print('Upstream pin:',rev,flush=True)
print('Scratch:',scratch,flush=True)
print('Only upstream change: test-only Keyshare OT accessors',flush=True)
result = subprocess.run(['cargo','run','--offline','--locked','--release','--manifest-path',str(probe/'Cargo.toml'),'--target-dir',str(root/'target/silence-dkls23')])
raise SystemExit(result.returncode)
