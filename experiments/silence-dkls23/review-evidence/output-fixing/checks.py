#!/usr/bin/env python3
"""Fixed-input algebra/model checks. Does not prove malicious output extraction."""
import argparse
import hashlib
import itertools
import json
from fractions import Fraction
from pathlib import Path

ORDER = int('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141',16)
PIN = 'af5ada2a2e573c2c8eac5b01f9bbc4bf1c331ac7'


def affine_challenge():
    # Exhaust every nonzero two-coordinate error, constant and challenge.
    q=7
    predicates=points=0
    for coeff in itertools.product(range(q),repeat=2):
        if coeff==(0,0): continue
        for constant in range(q):
            roots=sum((coeff[0]*x+coeff[1]*y+constant)%q==0
                      for x,y in itertools.product(range(q),repeat=2))
            assert roots==q
            predicates+=1
            points+=q*q
    # The fixed nonzero-vector hypothesis matters: zero errors can collide always.
    assert all((0*x+0*y)%q==0 for x,y in itertools.product(range(q),repeat=2))
    return {'field':q,'nonconstant_predicates':predicates,
            'challenge_evaluations':points,'roots_per_predicate':q,
            'bound':'1/q for uniform independent field challenges and fixed nonzero coefficients'}


def reduced_challenge():
    # Exact finite model of biased hash-to-field, not uniform-scalar sampling.
    q,bits=11,4
    raw=range(1<<bits)
    max_atom=max(sum(x%q==a for x in raw) for a in range(q))
    checked=0
    for a,b in itertools.product(range(q),repeat=2):
        if a==b==0: continue
        for constant in range(q):
            roots=sum((a*(x%q)+b*(y%q)+constant)%q==0
                      for x,y in itertools.product(raw,repeat=2))
            assert Fraction(roots,(1<<bits)**2)<=Fraction(max_atom,1<<bits)
            checked+=1
    atom=Fraction(((1<<256)+ORDER-1)//ORDER,1<<256)
    assert atom==Fraction(1,1<<255)
    return {'toy_predicates':checked,'toy_max_atom':str(Fraction(max_atom,1<<bits)),
            'secp256k1_reduced_uniform_256bit_max_atom':str(atom),
            'conditional_single_predicate_bound':'2^-255',
            'scope':'independent uniform raw challenge bytes; not a bound for Merlin or the full stack'}


def late_ot_control():
    # Section 4.5's abstract freedom: choose T1 after correction and challenge.
    q=101; rows=4; width=3
    correction=[[((j+3)*(i+7)+11)%q for i in range(width)] for j in range(rows)]
    theta=[int.from_bytes(hashlib.sha256(bytes(sum(correction,[]))+bytes([i])).digest(),'big')%q
           for i in range(2)]
    chi=theta+[1]
    v=17
    inconsistent=[[j+1,2*j+3,0] for j in range(rows)]
    for row in inconsistent: row[2]=(v-sum(x*y for x,y in zip(theta,row[:2])))%q
    assert len({tuple(row) for row in inconsistent})==rows
    alpha0=[[((j+5)*(i+9)+19)%q for i in range(width)] for j in range(rows)]
    # These are intentionally post-challenge chosen abstract OT outputs.
    alpha1=[[(alpha0[j][i]+inconsistent[j][i]-correction[j][i])%q
             for i in range(width)] for j in range(rows)]
    beta_cases=0
    for beta in itertools.product([0,1],repeat=rows):
        for j in range(rows):
            selected=alpha0[j] if beta[j]==0 else alpha1[j]
            d=[(selected[i]+beta[j]*correction[j][i])%q for i in range(width)]
            received=(sum(x*y for x,y in zip(chi,d))-beta[j]*v)%q
            target=sum(x*y for x,y in zip(chi,alpha0[j]))%q
            assert received==target
        beta_cases+=1
    return {'nonconstant_effective_rows':rows,'all_choice_vectors_accept':beta_cases,
            'scope':'abstract late-input OT counterexample, not an admissible compiled-stack attack'}


def xor_reduce(values):
    out=0
    for value in values:out^=value
    return out


def fixed_matrix_algebra():
    # Packed eight toy columns; four blocks of k=2 make one 8-bit Delta.
    enc=[[(29+i*41+j*17)&255 for j in range(4)] for i in range(4)]
    deltas=[0,1,2,3]
    dec=[row.copy() for row in enc]
    for i in range(4):dec[i][deltas[i]]=0
    V=[xor_reduce(enc[i][x] for x in range(4) if (x>>bit)&1)
       for i in range(4) for bit in range(2)]
    nabla=sum(delta<<(2*i) for i,delta in enumerate(deltas))
    assert nabla!=0
    correlated=malformed=0
    for bad in [False,True]:
        keys=[row.copy() for row in dec]
        if bad:keys[1][0]^=23  # Non-punctured mismatch, fixed before choices.
        baseline=None
        for beta in range(256):
            U=[xor_reduce(row)^beta for row in enc]
            W=[xor_reduce(keys[i][x] for x in range(4) if ((deltas[i]^x)>>bit)&1)
               ^ (U[i] if (deltas[i]>>bit)&1 else 0)
               for i in range(4) for bit in range(2)]
            fixed=[value ^ (beta if (deltas[i//2]>>(i%2))&1 else 0)
                   for i,value in enumerate(W)]
            if baseline is None:baseline=fixed
            assert fixed==baseline
            if not bad:
                assert fixed==V
                correlated+=1
            else:malformed+=1
            # For each column, unordered randomized pairs are fixed. Pair order
            # can swap with beta; correlation with H(V) is a separate property.
            for j in range(8):
                vcol=sum(((baseline[i]>>j)&1)<<i for i in range(8))
                wcol=sum(((W[i]>>j)&1)<<i for i in range(8))
                assert {wcol,wcol^nabla}=={vcol,vcol^nabla}
    return {'honest_correlated_choice_vectors':correlated,
            'fixed_malformed_seed_choice_vectors':malformed,
            'scope':'fixed seeds and fixed punctures; no extraction from malicious setup'}


def online_fixing_control():
    # A definition/model control: an effective-input handle must be fixed before
    # its candidate challenge answer, not reconstructed from the final transcript.
    class Prefix:
        def __init__(self):self.fixed={};self.answered={}
        def fix(self,candidate,pads):
            if candidate in self.answered:raise ValueError('late extraction')
            if candidate in self.fixed and self.fixed[candidate]!=pads:raise ValueError('equivocation')
            self.fixed[candidate]=pads
        def query(self,candidate):
            if candidate not in self.fixed:raise ValueError('unfixed inputs')
            self.answered[candidate]=hashlib.sha256(candidate.encode()).hexdigest()
            return self.answered[candidate]
    prefix=Prefix()
    rejected=0
    for n in range(4):prefix.fix(str(n),(n,n+1));prefix.query(str(n))
    for candidate,pads in [('0',(99,100)),('new',(1,2))]:
        try:
            if candidate=='new':prefix.query(candidate)
            else:prefix.fix(candidate,pads)
        except ValueError:rejected+=1
        else:raise AssertionError('negative control escaped')
    assert rejected==2
    return {'candidate_queries':4,'late_or_unfixed_controls_refused':rejected,
            'scope':'ideal binding-interface model; not implemented by the research worker'}


def anchor(path,needle):
    lines=path.read_text().splitlines()
    for number,line in enumerate(lines,1):
        if needle in line:return {'path':str(path),'line':number,'needle':needle,
                                  'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
    raise AssertionError((path,needle))


def source_map(repo,registry):
    pkgs=list(registry.glob('*/sl-oblivious-1.0.0-beta'))
    assert len(pkgs)==1
    ot=pkgs[0]/'src'
    soft=ot/'soft_spoken/soft_spoken_ot.rs';vole=ot/'rvole.rs'
    s=soft.read_text();v=vole.read_text()
    # Syntax/order correspondence; explicitly not a malicious-security proof.
    sender=s[s.index('impl SoftSpokenOTSender'):s.index('pub fn generate_all_but_one_seed_ot')]
    assert sender.index('if q_row.ct_ne')<sender.index('let mut zeta = transpose_bool_matrix')
    assert 'hash_matrix_u.append_message(b"", &message.u[i])' in sender
    assert 'hash_matrix_u.append_message(b"", &message.x)' not in sender
    assert 'hash_matrix_u.append_message(b"", &message.t' not in sender
    sendvole=v[v.index('impl RVOLESender'):]
    assert sendvole.index('SoftSpokenOTSender::process')<sendvole.index('output.a_tilde.iter_mut()')<sendvole.index('let mut theta')
    native=repo/'.local/silence-dkls23/sources'/('dkls23-'+PIN)/'src/sign/dsg.rs'
    specs=[(soft,'pub struct ReceiverOTSeed'),(soft,'pub struct Round1Output'),
           (soft,'let extended_packed_choices'),(soft,'let mut matrix_hasher'),
           (soft,'let psi = transpose_bool_matrix'),(soft,'impl SoftSpokenOTSender'),
           (soft,'hash_matrix_u.append_message'),(soft,'let t_i_plus_delta_i_times_x'),
           (soft,'if q_row.ct_ne'),(soft,'let mut zeta = transpose_bool_matrix'),
           (vole,'rng.fill_bytes(&mut beta)'),(vole,'pub fn process('),
           (vole,'let sender_extended_output'),(vole,'for (j, a_tilde_j_ref)'),
           (vole,'let mut theta'),(native,'fn mta_session_id'),
           (repo/'experiments/silence-dkls23/src/d/material.rs','pub fn extract')]
    # Anchor the sender theta separately rather than silently using receiver theta.
    sender_theta_line=v[:v.index('let mut theta',v.index('impl RVOLESender'))].count('\n')+1
    return {'anchors':[anchor(p,n) for p,n in specs],
            'sender_theta_line':sender_theta_line,
            'extension_challenge_omits_x_t':True,
            'native_sender_computes_extension_before_correction_and_theta':True,
            'scope':'source correspondence only; checked order does not constrain arbitrary peer code'}


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--repo',type=Path,default=Path(__file__).resolve().parents[4])
    p.add_argument('--registry',type=Path,default=Path.home()/'.cargo/registry/src')
    p.add_argument('--native-evidence',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    native=json.loads(a.native_evidence.read_text())
    expected={'public_fixture_generations':4,'sessions_per_generation':4,
              'selected_pad_matches':8192,'same_context_replayed_rows':8192,
              'complementary_choice_swapped_rows':8192,'observed_different_sid_rows':6144,
              'rvole_product_identities':32,'unhashed_t_mutations_refused':16,
              'unhashed_x_mutations_refused':16,'simple_correction_mutations_refused':16}
    for k,value in expected.items():assert native[k]==value,(k,native[k])
    result={'analysis_base_commit':'7669f7d','native_pin':PIN,
            'affine_challenge':affine_challenge(),'reduced_challenge':reduced_challenge(),
            'late_ot_negative_control':late_ot_control(),
            'fixed_matrix_algebra':fixed_matrix_algebra(),
            'online_fixing_control':online_fixing_control(),
            'source_correspondence':source_map(a.repo,a.registry),
            'native_probe':native,
            'native_evidence_sha256':hashlib.sha256(a.native_evidence.read_bytes()).hexdigest(),
            'status':'conditional algebra and primitive correspondence; malicious prefix extraction remains open'}
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'evidence':str(a.output),'status':result['status']},indent=2))

if __name__=='__main__':main()
