#!/usr/bin/env python3
"""Programmable-ROM registration model, not a simulator for fixed SHA256.

Uses secp256k1 arithmetic and real Ed25519 authentication for public model frames.
No production Root/worker/native code is changed or loaded. The simulator API
receives only points; test drivers hold scalar witnesses independently.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
import secrets
import sys
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("donor_checks", HERE.parent/"donor-proof/checks.py")
curve = importlib.util.module_from_spec(spec)
spec.loader.exec_module(curve)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

Q, G = curve.ORDER, curve.GENERATOR


def negate(p):
    return None if p is None else (p[0], (-p[1]) % curve.FIELD)


def encode(p):
    assert p is not None
    return bytes([2+(p[1] & 1)])+p[0].to_bytes(32,"big")


def decode(b):
    assert len(b) == 33 and b[0] in [2,3]
    x = int.from_bytes(b[1:],"big")
    assert x < curve.FIELD
    square = (x*x*x+7) % curve.FIELD
    y = pow(square,(curve.FIELD+1)//4,curve.FIELD)
    assert y*y % curve.FIELD == square
    if (y & 1) != b[0]-2:
        y = (-y) % curve.FIELD
    return x,y


def compact(value):
    return json.dumps(value,separators=(",",":"),ensure_ascii=False).encode()


def digest_input(label,value):
    label = label.encode()
    body = compact(value)
    return len(label).to_bytes(4,"big")+label+len(body).to_bytes(8,"big")+body


def pool_input(label,fields):
    fields = [label.encode()]+list(fields)
    return b"\x00\x01"+b"".join(len(b).to_bytes(8,"big")+b for b in fields)


def hash_fixed(label,value):
    # Record/message digests are evaluated, not programmed, in this model.
    return hashlib.sha256(digest_input(label,value)).digest()


class ProgramCollision(Exception):
    pass


class BadLateOpening(Exception):
    pass


class Oracle:
    def __init__(self):
        self.answers = {}
        self.public_queries = []
        self.programs = 0

    def query(self,kind,key,metadata=None,public=True):
        index = (kind,key)
        if index not in self.answers:
            self.answers[index] = secrets.token_bytes(32)
        if public:
            self.public_queries.append((kind,key,copy.deepcopy(metadata),self.answers[index]))
        return self.answers[index]

    def program_fresh(self,kind,key,value):
        index = (kind,key)
        if index in self.answers:
            raise ProgramCollision("refuse to overwrite an answered oracle input")
        self.answers[index] = value
        self.programs += 1

    def extract(self,wallet,role,commitment):
        # Parse actual query bytes. Caller-supplied test metadata is not evidence.
        matches = []
        label = b"pairkey/d/registration-commit/v2"
        prefix = len(label).to_bytes(4,"big")+label
        for kind,key,_,out in self.public_queries:
            if kind != "commit" or out != commitment or not key.startswith(prefix):
                continue
            tail = key[len(prefix):]
            if len(tail) < 8 or int.from_bytes(tail[:8],"big") != len(tail)-8:
                continue
            try:
                payload = json.loads(tail[8:])
                w,r,opening = payload
                if w != wallet or type(r) is not int or r != role:
                    continue
                if not isinstance(opening,dict) or set(opening) != {"point","salt"}:
                    continue
                point,salt = opening["point"],opening["salt"]
                if not isinstance(point,list) or not isinstance(salt,list) or len(salt) != 32:
                    continue
                if any(type(x) is not int or not 0 <= x < 256 for x in point+salt):
                    continue
                canonical = {"point":point,"salt":salt}
                if key != digest_input(label.decode(),[wallet,role,canonical]):
                    continue
                matches.append(canonical)
            except (ValueError,TypeError,KeyError,UnicodeDecodeError):
                continue
        if not matches:
            return None
        assert all(m == matches[0] for m in matches), "binding collision in model"
        return copy.deepcopy(matches[0])


def commitment(oracle,wallet,role,opening,public=True):
    payload = [wallet,role,opening]
    key = digest_input("pairkey/d/registration-commit/v2",payload)
    return oracle.query("commit",key,payload,public)


def record(wallet,commitments,openings):
    root = curve.point_add(decode(bytes(openings[0]["point"])),decode(bytes(openings[1]["point"])))
    assert root is not None
    public = list(encode(root))
    return {"wallet":wallet,"configuration":[17]*32,"commitments":[list(c) for c in commitments],
            "openings":openings,"public_key":public,
            "chain_code":list(hash_fixed("pairkey/dkls-research/public-chain-code/v1",
                                          [wallet["key_id"],public]))}


def record_digest(r):
    return hash_fixed("pairkey/d/record/v2",r)


def proof_input(r,role,nonce_point):
    return pool_input("pairkey/d/possession-proof/v2",
                      [record_digest(r),bytes([role]),nonce_point])


def authenticate(e,key):
    message = hash_fixed("pairkey/d/endorsement/v2",
                         [e["record"],e["role"],e["commitment"],e["response"]])
    e["signature"] = list(key.sign(message))
    return e


def verify(oracle,r,e,key):
    assert e["record"] == list(record_digest(r))
    message = hash_fixed("pairkey/d/endorsement/v2",
                         [e["record"],e["role"],e["commitment"],e["response"]])
    key.verify(bytes(e["signature"]),message)
    a = decode(bytes(r["openings"][e["role"]]["point"]))
    nonce = decode(bytes(e["commitment"]))
    raw = oracle.query("proof",proof_input(r,e["role"],bytes(e["commitment"])))
    challenge = int.from_bytes(raw,"big") % Q
    z = int.from_bytes(bytes(e["response"]),"big")
    assert z < Q
    assert curve.point_mul(z,G) == curve.point_add(nonce,curve.point_mul(challenge,a))


def real_proof(oracle,r,role,witness,key):
    nonce = int.from_bytes(secrets.token_bytes(64),"big") % Q
    assert nonce != 0
    point = encode(curve.point_mul(nonce,G))
    raw = oracle.query("proof",proof_input(r,role,point))
    challenge = int.from_bytes(raw,"big") % Q
    return authenticate({"role":role,"record":list(record_digest(r)),
                         "commitment":list(point),
                         "response":list(((nonce+challenge*witness)%Q).to_bytes(32,"big"))},key)


class Simulator:
    def __init__(self,oracle,honest_role,key):
        self.oracle, self.role, self.key = oracle,honest_role,key
        self.slots = {}

    @staticmethod
    def domain(wallet):
        return hash_fixed("pairkey/d/wallet-domain/v2",wallet)

    def begin(self,wallet):
        domain = self.domain(wallet)
        if domain in self.slots:
            raise ValueError("no second fresh ceremony for this domain")
        commit = secrets.token_bytes(32)
        self.slots[domain] = {"stage":"reserved","wallet":copy.deepcopy(wallet),"commit":commit}
        return commit

    def reveal(self,wallet,peer_commit,ideal_public):
        slot = self.slots[self.domain(wallet)]
        assert slot["stage"] == "reserved"
        opening = self.oracle.extract(wallet,1-self.role,peer_commit)
        try:
            peer_point = decode(bytes(opening["point"])) if opening is not None else None
        except (AssertionError,ValueError,OverflowError):
            peer_point = None
        # Invalid/no-query commitments do not justify skipping honest reveal.
        # Emit a uniform fallback point, then fail at the peer-opening boundary.
        honest_point = (curve.point_add(ideal_public,negate(peer_point))
                        if peer_point is not None else ideal_public)
        assert honest_point is not None
        own = {"point":list(encode(honest_point)),"salt":list(secrets.token_bytes(32))}
        key = digest_input("pairkey/d/registration-commit/v2",[wallet,self.role,own])
        self.oracle.program_fresh("commit",key,slot["commit"])
        assert commitment(self.oracle,wallet,self.role,own) == slot["commit"]
        slot.update(stage="revealed",own=own,peer=opening,peer_commit=peer_commit,
                    peer_validated=False)
        return own

    def validate_peer_opening(self,wallet,opening):
        slot = self.slots[self.domain(wallet)]
        if commitment(self.oracle,wallet,1-self.role,opening) != slot["peer_commit"]:
            raise ValueError("authenticated reveal mismatch")
        if slot["peer"] is None:
            raise BadLateOpening("valid opening without a prior matching query")
        assert slot["peer"] == opening, "binding collision after extraction"
        try:
            decode(bytes(opening["point"]))
        except (AssertionError,ValueError,OverflowError) as error:
            raise ValueError("invalid committed point") from error
        slot["peer_validated"] = True

    def endorse(self,wallet):
        slot = self.slots[self.domain(wallet)]
        assert slot["stage"] == "revealed" and slot["peer_validated"]
        openings,commits = [None,None],[None,None]
        openings[self.role],openings[1-self.role] = slot["own"],slot["peer"]
        commits[self.role],commits[1-self.role] = slot["commit"],slot["peer_commit"]
        r = record(wallet,commits,openings)
        # No honest scalar witness is received or reconstructed here.
        raw = secrets.token_bytes(32)
        challenge = int.from_bytes(raw,"big") % Q
        z = secrets.randbelow(Q)
        a = decode(bytes(slot["own"]["point"]))
        nonce = curve.point_add(curve.point_mul(z,G),negate(curve.point_mul(challenge,a)))
        assert nonce is not None
        nonce_bytes = encode(nonce)
        self.oracle.program_fresh("proof",proof_input(r,self.role,nonce_bytes),raw)
        e = authenticate({"role":self.role,"record":list(record_digest(r)),
                          "commitment":list(nonce_bytes),"response":list(z.to_bytes(32,"big"))},self.key)
        verify(self.oracle,r,e,self.key.public_key())
        slot.update(stage="prepared",record=r,endorsement=e)
        return copy.deepcopy(r),copy.deepcopy(e)

    def restart(self,wallet):
        slot = self.slots[self.domain(wallet)]
        if slot["stage"] in ["reserved","revealed"]:
            slot["stage"] = "retired"
            raise ValueError("incomplete slot permanently retired")
        if slot["stage"] not in ["prepared","active"]:
            raise ValueError("retired slot")
        return copy.deepcopy(slot["record"]),copy.deepcopy(slot["endorsement"])

    def activate(self,wallet,r,own_endorsement,peer_endorsement,peer_key):
        slot = self.slots[self.domain(wallet)]
        assert slot["stage"] == "prepared"
        assert r == slot["record"] and own_endorsement == slot["endorsement"]
        assert peer_endorsement["role"] == 1-self.role
        verify(self.oracle,r,peer_endorsement,peer_key)
        slot["stage"] = "active"

    def agree_saved_record(self,wallet,peer_record):
        slot = self.slots[self.domain(wallet)]
        if slot["stage"] not in ["prepared","active"] or peer_record != slot["record"]:
            raise ValueError("asymmetric/conflicting prepared registration")


def wallet(keys,index):
    return {"version":2,"identities":[list(k.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)) for k in keys],
            "namespace":"pairkey/registration/model/λ","epoch":0,"key_id":list(index.to_bytes(32,"big"))}


def normalization_checks():
    rows = []
    for honest in [0,1]:
        h,c = honest+1,2-honest
        lambdas = [2,-1]
        # Nonzero test scalars; the simulator does not use them.
        b,p0,slope = 19,37,41
        check_h = 0
        check_c = b*pow(lambdas[1-honest]%Q,-1,Q) % Q
        # A linear polynomial through check_h at h and check_c at c.
        check_slope = (check_c-check_h)*pow((c-h)%Q,-1,Q) % Q
        check_constant = (check_h-h*check_slope) % Q
        raw = [(check_constant+check_slope*t+p0+slope*t)%Q for t in [1,2]]
        rho = (p0+slope*c) % Q
        shifts = [(-t*rho*pow(c,-1,Q))%Q for t in [1,2]]
        normalized = [(x+u)%Q for x,u in zip(raw,shifts)]
        raw_root = (2*raw[0]-raw[1])%Q
        assert (2*normalized[0]-normalized[1])%Q == raw_root
        assert normalized[1-honest] == check_c
        a = lambdas[honest]*normalized[honest] % Q
        assert (a+b)%Q == raw_root
        assert sum(l*u for l,u in zip(lambdas,shifts))%Q == 0
        z = [71,(-71)%Q]
        assert [(l*s+mask)%Q for l,s,mask in zip(lambdas,normalized,z)] == [
            (l*s+mask+l*u)%Q for l,s,mask,u in zip(lambdas,raw,z,shifts)]
        small = 101
        distribution,naive_matches = set(),0
        for constant in range(small):
            for linear in range(small):
                extra = (constant+c*linear)%small
                honest_raw = (constant+h*linear)%small
                honest_normal = (honest_raw-h*extra*pow(c,-1,small))%small
                contribution = lambdas[honest]*honest_normal%small
                assert contribution == constant
                distribution.add((contribution,extra))
                naive_matches += (extra == 0)
        assert len(distribution) == small*small
        assert naive_matches == small
        rows.append({"honest_role":honest,"key_preserved":True,
                     "corrupt_coordinate_fixed":True,"weighted_shifts_sum_zero":True,
                     "small_field":small,"all_polynomials_checked":small*small,
                     "normalized_contribution_and_extra_are_bijective":True,
                     "naive_direct_map_matches":naive_matches})
    return rows


def run():
    keys = [Ed25519PrivateKey.generate(),Ed25519PrivateKey.generate()]
    completed = []
    for role in [0,1]:
        oracle = Oracle()
        sim = Simulator(oracle,role,keys[role])
        pending = []
        for i in range(6):
            w = wallet(keys,role*100+i)
            own_commit = sim.begin(w)
            corrupt_witness = secrets.randbelow(Q-1)+1
            peer = {"point":list(encode(curve.point_mul(corrupt_witness,G))),
                    "salt":list(secrets.token_bytes(32))}
            cc = commitment(oracle,w,1-role,peer)
            ideal_secret = secrets.randbelow(Q-1)+1
            ideal_public = curve.point_mul(ideal_secret,G)
            own = sim.reveal(w,cc,ideal_public)
            assert curve.point_add(decode(bytes(own["point"])),decode(bytes(peer["point"]))) == ideal_public
            assert oracle.extract(w,role,cc) is None
            altered = copy.deepcopy(w);altered["epoch"] += 1
            assert oracle.extract(altered,1-role,cc) is None
            sim.validate_peer_opening(w,peer)
            pending.append((w,corrupt_witness,own_commit))
        # Complete domains in reverse order to exercise interleaved oracle state.
        for w,b,_ in reversed(pending):
            r,e = sim.endorse(w)
            assert sim.restart(w) == (r,e)
            try:
                sim.agree_saved_record(w,None)
            except ValueError:
                pass
            else:
                raise AssertionError("asymmetric prepare resumed")
            changed_record = copy.deepcopy(r);changed_record["wallet"]["epoch"] += 1
            try:
                sim.agree_saved_record(w,changed_record)
            except ValueError:
                pass
            else:
                raise AssertionError("conflicting record resumed")
            sim.agree_saved_record(w,r)
            try:
                sim.begin(w)
            except ValueError:
                pass
            else:
                raise AssertionError("fresh retry after disclosure")
            wrong = copy.deepcopy(e);wrong["response"][0] ^= 1
            peer_e = real_proof(oracle,r,1-role,b,keys[1-role])
            try:
                sim.activate(w,r,wrong,peer_e,keys[1-role].public_key())
            except AssertionError:
                pass
            else:
                raise AssertionError("changed local endorsement accepted")
            sim.activate(w,r,e,peer_e,keys[1-role].public_key())
            assert sim.restart(w) == (r,e)
            completed.append(hashlib.sha256(compact(r)).hexdigest())
        for phase in ["reserved","revealed"]:
            w = wallet(keys,role*1000+900+(phase == "revealed"))
            sim.begin(w)
            if phase == "revealed":
                peer = {"point":list(encode(curve.point_mul(23,G))),"salt":list(secrets.token_bytes(32))}
                cc = commitment(oracle,w,1-role,peer)
                sim.reveal(w,cc,curve.point_mul(53,G))
            try:
                sim.restart(w)
            except ValueError:
                assert sim.slots[sim.domain(w)]["stage"] == "retired"
            else:
                raise AssertionError("incomplete slot recovered")
        key = b"prequeried"
        old = oracle.query("proof",key)
        try:
            oracle.program_fresh("proof",key,b"x"*32)
        except ProgramCollision:
            assert oracle.query("proof",key) == old
        else:
            raise AssertionError("oracle answer overwritten")
        missing = wallet(keys,9999+role)
        assert oracle.extract(missing,1-role,secrets.token_bytes(32)) is None
        fake = {"point":list(encode(curve.point_mul(23,G))),"salt":[7]*32}
        spoof = oracle.query("commit",b"not a commitment encoding",[missing,1-role,fake])
        assert oracle.extract(missing,1-role,spoof) is None
        direct_key = digest_input("pairkey/d/registration-commit/v2",[missing,1-role,fake])
        direct = oracle.query("commit",direct_key)
        assert oracle.extract(missing,1-role,direct) == fake
        for invalid in ["no-query","invalid-point"]:
            w = wallet(keys,80000+role*100+(invalid == "invalid-point"))
            own_commit = sim.begin(w)
            bad_opening = {"point":list(encode(curve.point_mul(23,G))) if invalid == "no-query" else [255]*33,
                           "salt":list(secrets.token_bytes(32))}
            cc = (secrets.token_bytes(32) if invalid == "no-query"
                  else commitment(oracle,w,1-role,bad_opening))
            own = sim.reveal(w,cc,curve.point_mul(53,G))
            assert commitment(oracle,w,role,own) == own_commit
            try:
                sim.validate_peer_opening(w,bad_opening)
            except ValueError:
                pass
            else:
                raise AssertionError("invalid opening accepted")
            assert sim.slots[sim.domain(w)]["stage"] == "revealed"
        assert digest_input("pairkey/d/registration-commit/v2",[missing,role,{}])[:2] == b"\0\0"
        assert pool_input("pairkey/d/possession-proof/v2",[])[:2] == b"\0\1"
    return {"model":"programmable ROM with simulated PKI; not actual fixed SHA256",
            "implementation":"3b065e5799c76240c7d9f14920636fe3003dfb6a",
            "simulated_certificates":len(completed),"both_honest_roles":True,
            "witnessless_honest_endorsements_verify":True,
            "same_saved_endorsement_on_resume":True,
            "asymmetric_and_conflicting_prepared_records_refuse":True,
            "incomplete_resume_retires":True,"domain_role_extraction_separation":True,
            "extraction_parses_query_bytes_and_ignores_untrusted_metadata":True,
            "prequeried_input_programming_refused":True,
            "invalid_or_unqueried_commitment_rejects_after_honest_reveal":True,
            "normalization":normalization_checks(),"public_record_hashes":completed,
            "proof_status":"model consistency evidence; theorem and composition require independent review"}


def check_native(path):
    vectors = json.loads(path.read_text())
    w = json.loads(vectors["wallet_json"])
    opening = json.loads(vectors["opening_json"])
    r = json.loads(vectors["record_json"])
    e = json.loads(vectors["endorsement_json"])
    assert list(hash_fixed("pairkey/d/wallet-domain/v2",w)) == vectors["wallet_digest"]
    assert list(hash_fixed("pairkey/d/registration-commit/v2",[w,0,opening])) == vectors["commitment"]
    assert list(record_digest(r)) == vectors["record_digest"]
    assert list(hashlib.sha256(proof_input(r,0,bytes(e["commitment"]))).digest()) == vectors["proof_challenge"]
    message = hash_fixed("pairkey/d/endorsement/v2",[e["record"],0,e["commitment"],e["response"]])
    assert list(message) == vectors["endorsement_message"]

    class FixedOracle:
        def query(self,kind,key):
            return hashlib.sha256(key).digest()

    verify(FixedOracle(),r,e,Ed25519PublicKey.from_public_bytes(bytes(w["identities"][0])))
    assert vectors["native_endorsement_validation"] is True
    return {"fixed_hash_encodings_match_rust":True,
            "fixed_hash_endorsement_verifies_in_both":True,
            "scope":"separate from programmable-ROM simulation"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--native-vectors",type=Path)
    args = parser.parse_args()
    report = run()
    if args.native_vectors:
        report["native_correspondence"] = check_native(args.native_vectors)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({"evidence":str(args.output),"simulated_certificates":report["simulated_certificates"],
                      "status":report["proof_status"]},indent=2))
