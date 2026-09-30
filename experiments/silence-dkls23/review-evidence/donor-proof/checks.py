#!/usr/bin/env python3
"""Exact algebra/bias checks and source correspondence, not a security proof.

Uses public toy values only. Reads pinned sources without changing them.
Python 3 standard library; run with --output /absolute/evidence.json.
"""
import argparse
import ast
import hashlib
import json
import math
import operator
from fractions import Fraction
from pathlib import Path

ORDER = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
FIELD = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
GENERATOR = (
    int("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16),
    int("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16),
)
PIN = "af5ada2a2e573c2c8eac5b01f9bbc4bf1c331ac7"


def scale(c, v):
    return tuple(c * x for x in v)


def add(a, b):
    return tuple(x + y for x, y in zip(a, b))


def linear_identities():
    # Coefficients of arbitrary (a,b,child_offset,zeta), over an odd-order field.
    a, b, delta, zeta = [tuple(Fraction(i == j) for i in range(4)) for j in range(4)]
    s0, s1 = scale(Fraction(1, 2), a), scale(-1, b)
    aggregate = add(scale(2, s0), scale(-1, s1))
    assert aggregate == add(a, b)
    slope = add(scale(Fraction(-1, 2), a), scale(-1, b))
    assert add(aggregate, slope) == s0
    assert add(aggregate, scale(2, slope)) == s1
    sk0 = add(add(scale(2, s0), scale(Fraction(1, 2), delta)), scale(-1, zeta))
    sk1 = add(add(scale(-1, s1), scale(Fraction(1, 2), delta)), zeta)
    assert add(sk0, sk1) == add(aggregate, delta)
    return {"coefficient_identity": "2*(a/2)-(-b)=a+b",
            "polynomial": "p(t)=a+b+t*(-a/2-b)",
            "child_and_mask_identity": "(a+delta/2-zeta)+(b+delta/2+zeta)=a+b+delta",
            "scope": "identities for every field assignment, not distributional/UC security"}


def reduction_bias(bits):
    n = 1 << bits
    remainder = n % ORDER
    distance = Fraction(remainder * (ORDER - remainder), ORDER * n)
    # Count the r heavy residues and q-r light residues exactly.
    heavy = Fraction(n // ORDER + 1, n) - Fraction(1, ORDER)
    light = Fraction(1, ORDER) - Fraction(n // ORDER, n)
    assert distance == (remainder * heavy + (ORDER - remainder) * light) / 2
    assert distance <= Fraction(ORDER, 4 * n)
    return {"bits": bits, "tv_numerator": distance.numerator,
            "tv_denominator": distance.denominator,
            "negative_log2_tv": math.log2(distance.denominator) - math.log2(distance.numerator),
            "scope": "uniform-bit reduction only, conditional on uniform input"}


def point_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    x, y = p
    u, v = q
    if x == u and (y + v) % FIELD == 0:
        return None
    slope = ((3*x*x) * pow(2*y, -1, FIELD) if p == q
             else (v-y) * pow(u-x, -1, FIELD)) % FIELD
    rx = (slope*slope-x-u) % FIELD
    return rx, (slope*(x-rx)-y) % FIELD


def point_mul(n, p):
    out = None
    n %= ORDER
    while n:
        if n & 1:
            out = point_add(out, p)
        p = point_add(p, p)
        n >>= 1
    return out


def verify_prehash(digest, signature, public):
    r, s = signature
    w = pow(s, -1, ORDER)
    result = point_add(point_mul(digest*w, GENERATOR), point_mul(r*w, public))
    return result is not None and result[0] % ORDER == r


def prehash_equivalence():
    # Public, unfunded toy secret and nonce; no PairKey roots are read.
    x, nonce, h = 7, 3, 1
    r = point_mul(nonce, GENERATOR)[0] % ORDER
    s = ((h+r*x)*pow(nonce, -1, ORDER)) % ORDER
    s = min(s, ORDER-s)
    public = point_mul(x, GENERATOR)
    assert h != h+ORDER and h+ORDER < (1 << 256)
    assert verify_prehash(h, (r, s), public)
    assert verify_prehash(h+ORDER, (r, s), public)
    return {"distinct_raw_prehashes_verify_same_signature": True,
            "claim": "fresh raw 32-byte prehash is not a valid unforgeability target",
            "required_equivalence": "actual child public key and digest modulo group order",
            "scope": "standard ECDSA arithmetic, not a demonstrated PairKey exploit"}


OPS = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
       ast.Div: operator.floordiv, ast.LShift: operator.lshift,
       ast.RShift: operator.rshift}


def integer_expr(node, names):
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    if isinstance(node, ast.Name):
        return names[node.id]
    if isinstance(node, ast.BinOp) and type(node.op) in OPS:
        return OPS[type(node.op)](integer_expr(node.left, names), integer_expr(node.right, names))
    raise ValueError("unsupported constant expression")


def read_parameters(path):
    import re
    values = {}
    for name, expr in re.findall(r"pub const (\w+): usize = ([^;]+);", path.read_text()):
        values[name] = integer_expr(ast.parse(expr.strip(), mode="eval").body, values)
    for key, value in {"KAPPA":256, "LAMBDA_C":256, "LAMBDA_S":128,
                       "S":128, "L_BATCH":2, "RHO":1, "SOFT_SPOKEN_K":4,
                       "L":512, "L_PRIME":640, "OT_WIDTH":3,
                       "LAMBDA_C_DIV_SOFT_SPOKEN_K":64}.items():
        assert values[key] == value, (key, values[key])
    return values


def variant_iii(m, s, q_bits=256):
    # 2026/976 Theorem 4.4 / B.17, a sufficient condition in RSOT hybrid.
    # Floating values are illustrative; no rounding-sensitive decision is used
    # for the 512 vs 2047 comparison at s=128.
    return q_bits+7*s+2*math.log2(s+1)+2*s*math.log2(math.e*m/s)


def parameters_comparison(values):
    m, kappa = values["L"], 128
    assert 256 >= kappa+2*math.log2(m)
    rows = []
    for s in [12, 13, 60, 128]:
        required = m
        while required < variant_iii(required, s):
            required += 1
        rows.append({"statistical_s":s, "rhs_at_m512":variant_iii(m,s),
                     "m512_satisfies_dimension_inequality":m >= variant_iii(m,s),
                     "minimum_integer_m_starting_at512":required})
    truncated = 256+7*35+2*math.log2(36)
    assert truncated <= m and variant_iii(m,35) > m
    p = Fraction(1, 1 << 12)
    # Hypothetical Bernoulli trial calculation, not a claimed attack rate.
    detection_trials = math.ceil(math.log(0.05)/math.log1p(-float(p)))
    assert (1-float(p))**detection_trials <= 0.05
    assert (1-float(p))**(detection_trials-1) > 0.05
    return {"hypothetical_computational_query_budget_bits":kappa,
            "secp256k1_log2_q_rounded":256, "rows":rows,
            "invalid_35_bit_truncation":{"rhs_with_missing_term":truncated,
                "full_rhs":variant_iii(m,35), "full_table_contains_the_term":True},
            "hypothetical_p2minus12_trial_detection":{
                "zero_success_probability_at4096":(1-float(p))**4096,
                "trials_for95percent_chance_at_least_one":detection_trials,
                "caveat":"B.17 establishes neither this attack rate nor an attack strategy"},
            "status":"comparison only; RSOT premise not established for compiled EndemicOT stack",
            "not_claimed":"system security bits, a practical attack, or a parameter update"}


def source_anchor(path, needle):
    lines = path.read_text().splitlines()
    for number, line in enumerate(lines, 1):
        if needle in line:
            return {"path":str(path), "line":number, "needle":needle,
                    "sha256":hashlib.sha256(path.read_bytes()).hexdigest()}
    raise AssertionError((path, needle))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[4])
    parser.add_argument("--registry", type=Path, default=Path.home()/".cargo/registry/src")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    exp = args.repo/"experiments/silence-dkls23"
    native = args.repo/".local/silence-dkls23/sources"/("dkls23-"+PIN)
    packages = list(args.registry.glob("*/sl-oblivious-1.0.0-beta"))
    assert len(packages) == 1, "choose an unambiguous pinned registry"
    ot = packages[0]
    specs = [
        (exp/"src/d.rs", "pub fn derive_v2"),
        (exp/"src/d.rs", "pub fn hedged_seed"),
        (exp/"src/d_worker.rs", "async fn register"),
        (exp/"src/d_worker.rs", "async fn prepare"),
        (exp/"src/d_worker.rs", "async fn sign"),
        (exp/"src/d/material.rs", "pub fn extract"),
        (exp/"src/d/material.rs", "pub fn package"),
        (exp/"patches/research-keyshare.rs", "pub fn pairkey_research_two_party"),
        (native/"src/sign/dsg.rs", "let final_session_id:"),
        (native/"src/sign/dsg.rs", "let digest_i:"),
        (native/"src/sign/dsg.rs", "fn get_zeta_i"),
        (native/"src/sign/dsg.rs", "fn mta_session_id"),
        (native/"src/keygen/keyshare.rs", "pub fn derive_with_offset"),
        (ot/"src/endemic_ot.rs", "m_b_values[random_choice_bit as usize]"),
        (ot/"src/soft_spoken/all_but_one.rs", "pub fn eval_pprf"),
        (ot/"src/soft_spoken/soft_spoken_ot.rs", "pub struct SoftSpokenOTSender"),
        (ot/"src/rvole.rs", "fn generate_gadget_vec"),
    ]
    params = read_parameters(ot/"src/params.rs")
    # Structural assertions do not prove semantic extraction or distribution.
    rvole = (ot/"src/rvole.rs").read_text()
    assert rvole.index("generate_gadget_vec(&session_id).enumerate()") < rvole.index("pub fn process(")
    assert 't.append_message(b"session-id", session_id)' in rvole
    selection = {"uniform_choice_bit_conditioned_on_selected_branch_acceptance":1,
                 "ideal_unconditional_bit_probability":0.5,
                 "acceptance_conditioned_distribution_is_not_all_honest":True,
                 "scope":"existing native selective-abort regression; this entry is its logical consequence"}
    report = {"implementation_commit":"0f6e0557555b73aafa15ce0b590067dad0a747d1",
              "native_pin":PIN, "algebra":linear_identities(),
              "scalar_reduction_bias":[reduction_bias(256), reduction_bias(512)],
              "claim_counterexample":prehash_equivalence(),
              "accepted_setup_distribution":selection,
              "compiled_parameters":params,
              "2026_variant_iii_comparison":parameters_comparison(params),
              "honest_sid_collision_union_bounds":{
                  str(n):str(Fraction(n*(n-1),2*(1<<256))) for n in [100,1000]},
              "sid_bound_premise":"independent uniform 256-bit honest SIDs; add PRG/entropy advantage",
              "sources":[source_anchor(*spec) for spec in specs],
              "overall_security_bound":"unavailable: reusable OT realization, RVOLE applicability, registration and child-key composition remain conditional"}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({"evidence":str(args.output), "algebra_checks":"passed",
                      "prehash_equivalence":"confirmed", "params":"unchanged",
                      "overall_security_bound":report["overall_security_bound"]},indent=2))


if __name__ == "__main__":
    main()
