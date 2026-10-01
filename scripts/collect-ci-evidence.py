#!/usr/bin/env python3
"""Copy only known public JSON reports; never upload worker roots/identities/ledgers."""
import json
import re
import hashlib
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path
import shutil
root = Path(__file__).resolve().parents[1]
report = root / '.local/ci-report'
for log, event, filename in [('ed25519-demo.log', 'local_demo_passed', 'ed25519-evidence.json'), ('multi-demo.log', 'multi_demo_complete', 'multi-evidence.json')]:
    found = []
    for line in (report / log).read_text().splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict) and item.get('event') == event:
            found.append(item)
    if len(found) != 1:
        raise SystemExit(f'Missing or ambiguous completion in {log}')
    path = Path(found[0]['evidence']).resolve()
    if not path.is_relative_to(root / '.local') or path.name not in ('evidence.json', 'multi-evidence.json'):
        raise SystemExit('Unexpected evidence path')
    evidence = json.loads(path.read_text())
    if log == 'multi-demo.log':
        flows = evidence.get('flows', [])
        if {(x.get('authorization'), x.get('suite')) for x in flows} != {(a, s) for a in ('account', 'program_cpi') for s in ('Dkls23Secp256k1', 'FrostRedPallas')}:
            raise SystemExit('Missing multi-suite flows')
        checks = ('missing_approval_refused', 'workers_refused_substitutions', 'tampered_receipt_refused', 'restart_preserved_key', 'freeze_refused')
        if not all(all(x.get(check) for check in checks) for x in flows):
            raise SystemExit('Failed multi-suite evidence')
        sessions = evidence.get('evm_sessions', [])
        session_checks = ('executed_without_commit', 'revocation_refused', 'limits_refused', 'policy_version_refused', 'required_commit_enforced', 'commit_plus_session_signed', 'transaction_replay_refused')
        if len(sessions) != 2 or {x.get('authorization') for x in sessions} != {'account', 'program_cpi'} or not all(all(x.get(check) is True for check in session_checks) for x in sessions):
            raise SystemExit('Missing EVM session evidence')
    shutil.copyfile(path, report / filename)
print('Public CI evidence collected')

def passed(log):
    results = re.findall(r'test result: ok\. (\d+) passed;', (report / log).read_text())
    if not results:
        raise SystemExit(f'Missing test results in {log}')
    return sum(map(int, results))
artifacts = ['Cargo.lock', 'target/deploy/pair_registry.so', 'target/deploy/example_controller.so', 'target/deploy/example_policy.so', 'target/debug/pairkey-worker', 'target/debug/pairkey-coordinator', 'target/debug/local_demo', 'target/silence-dkls23/release/dkls-spike']
hashes = {}
for filename in artifacts:
    with (root / filename).open('rb') as stream:
        hashes[filename] = hashlib.file_digest(stream, 'sha256').hexdigest()
validation = {'platform': platform.platform(), 'tool_versions': (report / 'versions.log').read_text().splitlines(), 'completed_at_utc': datetime.now(timezone.utc).isoformat(), 'base_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(), 'uncommitted_changes': bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=root, text=True).strip()), 'host_tests_passed': passed('host-tests.log'), 'registry_tests_passed': passed('registry-tests.log'), 'sbf_rebuilt': True, 'local_gate_passed': True, 'sha256': hashes}
(report / 'validation.json').write_text(json.dumps(validation, indent=2) + '\n')
