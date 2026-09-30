#!/usr/bin/env python3
"""Two-stage research review against frozen copies; no production source mutation."""
from pathlib import Path
import hashlib,json,shutil,subprocess,tarfile,tempfile
here=Path(__file__).resolve().parent
root=here.parents[3]
rev='af5ada2a2e573c2c8eac5b01f9bbc4bf1c331ac7'
archive=root/'.local/silence-dkls23/sources/dkls23.tar.gz'
assert hashlib.sha256(archive.read_bytes()).hexdigest()=='e7301fa0886c0232cdf7dad7b2827ef0ce0ea84c1853ea926fe781865d320c9b'
scratch=Path(tempfile.mkdtemp(prefix='pairkey-direct-review-',dir='/tmp'))
with tarfile.open(archive) as t:t.extractall(scratch,filter='data')
native=scratch/('dkls23-'+rev)
research=scratch/'research'
original=root/'experiments/silence-dkls23'
shutil.copytree(original/'src',research/'src')
for filename in ('Cargo.lock', 'patch-source.py'):
    shutil.copyfile(original/filename, research/filename)
shutil.copytree(original/'patches', research/'patches')
manifest=(original/'Cargo.toml').read_text()
manifest=manifest.replace('../../.local/silence-dkls23/sources/dkls23-'+rev,'../dkls23-'+rev)
manifest=manifest.replace('research-faults = ["sl-dkls23/pairkey-research-faults"]','research-faults = []')
(research/'Cargo.toml').write_text(manifest)
constructor=root/('.local/silence-dkls23/sources/dkls23-'+rev+'/src/keygen/pairkey_research.rs')
keyshare=native/'src/keygen/keyshare.rs'
keyshare.write_text(keyshare.read_text()+'\n'+constructor.read_text()+'''\nimpl Keyshare {
    /// Test-only extraction of correlated setup state; never logged.
    pub fn direct_review_material(&self) -> (SenderOTSeed, ReceiverOTSeed, [u8;32]) {
        let other=self.other(1-self.party_id);
        (other.send_ot_seed,other.recv_ot_seed,self.each(0).zeta_seed)
    }
}
''')
probe=scratch/'probe';(probe/'src').mkdir(parents=True)
shutil.copyfile(here/'main.rs',probe/'src/main.rs')
lock=here/'Cargo.lock.used'
shutil.copyfile(lock if lock.exists() else original/'Cargo.lock',probe/'Cargo.lock')
(probe/'Cargo.toml').write_text(f'''[package]
name="direct-derived-integration-probe"
version="0.1.0"
edition="2021"
[workspace]
[dependencies]
pairkey-dkls23-research={{path="../research"}}
sl-dkls23={{path="../dkls23-{rev}",default-features=false,features=["test-support","multi-thread"]}}
sl-mpc-mate={{version="=1.0.0-beta",features=["simple-relay"]}}
sl-oblivious="=1.0.0-beta"
k256={{version="=0.13.4",features=["ecdsa"]}}
tokio={{version="=1.48.0",features=["macros","rt-multi-thread","time"]}}
derivation-path="=0.2.0"
serde_json="=1.0.145"
zeroize="=1.8.1"
''')
source_files = list((original/'src').rglob('*.rs')) + list((original/'patches').rglob('*'))
source_files += [original/'Cargo.toml', original/'Cargo.lock', original/'patch-source.py', archive]
inputs={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(source_files) if p.is_file()}
inputs[str(constructor.relative_to(root))]=hashlib.sha256(constructor.read_bytes()).hexdigest()
(here/'reviewed-source-hashes.json').write_text(json.dumps(inputs,indent=2)+'\n')
print('Upstream pin:',rev,flush=True);print('Scratch:',scratch,flush=True)
print('Native additions: exact existing research constructor + test-only material accessor',flush=True)
args=['cargo','run','--offline','--release','--manifest-path',str(probe/'Cargo.toml'),'--target-dir',str(root/'target/silence-dkls23')]
if lock.exists():args.insert(3,'--locked')
r=subprocess.run(args)
if r.returncode==0:shutil.copyfile(probe/'Cargo.lock',lock)
raise SystemExit(r.returncode)
