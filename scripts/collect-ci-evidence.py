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
        if {(x.get('authorization'), x.get('suite')) for x in flows} != {(a, s) for a in ('account', 'program_cpi') for s in ('Dkls23Secp256k1', 'FrostRedPallas', 'FrostSecp256k1Tr')}:
            raise SystemExit('Missing multi-suite flows')
        checks = ('missing_approval_refused', 'workers_refused_substitutions', 'tampered_receipt_refused', 'restart_preserved_key', 'freeze_refused')
        if not all(all(x.get(check) for check in checks) for x in flows):
            raise SystemExit('Failed multi-suite evidence')
        sessions = evidence.get('evm_sessions', [])
        session_checks = ('executed_without_commit', 'revocation_refused', 'limits_refused', 'policy_version_refused', 'required_commit_enforced', 'commit_plus_session_signed', 'transaction_replay_refused')
        if len(sessions) != 2 or {x.get('authorization') for x in sessions} != {'account', 'program_cpi'} or not all(all(x.get(check) is True for check in session_checks) for x in sessions):
            raise SystemExit('Missing EVM session evidence')
        lifecycle = evidence.get('job_lifecycle', {})
        cases = lifecycle.get('cases', [])
        phases = ('register', 'prepare', 'sign', 'ecdsa_result', 'red_begin', 'red_finish', 'red_result')
        expected = {(p, a) for p in phases for a in ('cancel', 'coordinator_restart', 'worker_restart', 'policy_freeze') if a != 'policy_freeze' or not p.endswith('result')}
        if len(cases) != len(expected) or {(x.get('phase'), x.get('action')) for x in cases} != expected or not all(all(x.get(k) is True for k in ('explicit_fresh_retry_verified', 'duplicate_submission_deduplicated', 'cached_result_no_worker_calls')) for x in cases):
            raise SystemExit('Missing lifecycle matrix evidence')
        if lifecycle.get('authorization') != 'program_cpi' or not all(lifecycle.get(k) is True for k in ('completed_results_survive_restart', 'queued_cancellation_refused_before_start', 'sse_observed')):
            raise SystemExit('Missing durable job evidence')
    shutil.copyfile(path, report / filename)
print('Public CI evidence collected')

def passed(log):
    results = re.findall(r'test result: ok\. (\d+) passed;', (report / log).read_text())
    if not results:
        raise SystemExit(f'Missing test results in {log}')
    return sum(map(int, results))
if passed('native-faults.log') != 9 or passed('native-invariants.log') < 15:
    raise SystemExit('Native lifecycle gates did not execute the expected tests')
approval_gates = {}
for log, minimum in [
    ('offline-verifier-tests.log', 1),
    ('hosted-dkls-tests.log', 1),
    ('hosted-browser-tests.log', 1),
    ('approval-rules-tests.log', 4),
    ('controller-download.log', 4),
    ('program-approval-tests.log', 4),
    ('program-worker-tests.log', 3),
    ('hosted-policy-tests.log', 5),
]:
    count = passed(log)
    if count < minimum:
        raise SystemExit(f'Approval gate did not execute the expected tests: {log}')
    approval_gates[log.removesuffix('.log')] = count
browser_passes = re.findall(r'^# pass (\d+)$', (report / 'browser-unit-tests.log').read_text(), re.M)
if len(browser_passes) != 1 or int(browser_passes[0]) < 45:
    raise SystemExit('Browser approval and recovery tests did not execute')
approval_gates['browser-unit-tests'] = int(browser_passes[0])
host_output = (report / 'host-tests.log').read_text()
oidc_tests = (
    'hosted_oidc_fetches_https_keys_at_both_workers_and_binds_exact_request',
    'hosted_oidc_refuses_untrusted_tls_and_jwks_redirects',
)
for test in oidc_tests:
    if not re.search(r'^test \S*::' + re.escape(test) + r' \.\.\. ok$', host_output, re.M):
        raise SystemExit(f'Missing hosted OIDC transport coverage: {test}')
approval_gates['hosted-oidc-transport-tests'] = len(oidc_tests)
artifacts = ['Cargo.lock', 'target/deploy/pair_registry.so', 'target/deploy/example_controller.so', 'target/deploy/example_policy.so', 'target/debug/pairkey-worker', 'target/debug/pairkey-coordinator', 'target/debug/local_demo', 'target/silence-dkls23/release/dkls-spike']
hashes = {}
for filename in artifacts:
    with (root / filename).open('rb') as stream:
        hashes[filename] = hashlib.file_digest(stream, 'sha256').hexdigest()
validation = {'platform': platform.platform(), 'tool_versions': (report / 'versions.log').read_text().splitlines(), 'completed_at_utc': datetime.now(timezone.utc).isoformat(), 'base_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(), 'uncommitted_changes': bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=root, text=True).strip()), 'host_tests_passed': passed('host-tests.log'), 'native_lifecycle_tests_passed': passed('native-faults.log'), 'native_invariants_passed': passed('native-invariants.log'), 'registry_tests_passed': passed('registry-tests.log'), 'sbf_rebuilt': True, 'local_gate_passed': True, 'sha256': hashes}
validation['approval_gates_passed'] = approval_gates
(report / 'validation.json').write_text(json.dumps(validation, indent=2) + '\n')
