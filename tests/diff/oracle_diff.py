#!/usr/bin/env python3
"""Differential test: our ct01_audit_verify vs the independent naive oracle (DESIGN v0.3.4, A012 golden vectors).

  (a) our verifier over every golden vector/mode in audit/harness/vectors/expected.json;
  (b) chains written by OUR writer (gen_writer_chains) through the oracle.
Compares exit code, accept/fail and, on FAIL, the e_* reason name and number. The reference files are only
READ (SHA256SUMS verified first); everything we write goes to --workdir. Must run with a python3 that has
`cryptography` (the oracle needs it). Exit 0 = no unexpected difference.

  oracle_diff.py --verifier BIN --gen BIN --harness DIR --workdir DIR
"""
import argparse, hashlib, json, os, shutil, subprocess, sys

sys.dont_write_bytecode = True
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

# Known, analysed differences: (direction, vector, mode) -> explanation. Every entry must still differ,
# otherwise the test fails too (stale allowance). Empty for the A012 golden set.
EXPECTED_DIFF = {
    ("a", "neg_bitflip_body", "keyed"):
        "Flip of byte 50 (subj_first) of the first EVENT, CRC re-fixed, so subj_last < subj_first. DESIGN 6.2 order is "
        "'length -> structure -> crc -> fields -> seq/epoch -> link -> tag -> sig', so the field rule (4.2 subj range, "
        "e_field 11) fires before the tag. The oracle checks the 16/17/72 range inside its F70 block, AFTER the tag, "
        "so in keyed mode it reports e_tag (17); in public mode it reports e_field like us. Exit 2 / FAIL agree. "
        "Not tuned: our order follows 6.2.",
}


def sha256_file(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


def check_sums(harness):
    bad = []
    for line in open(os.path.join(harness, "SHA256SUMS")):
        line = line.strip()
        if not line:
            continue
        digest, name = line.split(None, 1)
        name = name.lstrip("*")
        p = os.path.join(harness, name)
        if not os.path.isfile(p) or sha256_file(p) != digest:
            bad.append(name)
    return bad


def pem_to_sec1(pem):
    k = serialization.load_pem_public_key(pem.encode())
    return k.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint).hex()


def sec1_to_pem(hexs):
    k = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(hexs))
    return k.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def run(args):
    p = subprocess.run(args, capture_output=True, text=True)
    lines = [l for l in p.stdout.splitlines() if l.strip()]
    try:
        j = json.loads(lines[-1]) if lines else {}
    except ValueError:
        j = {}
    return p.returncode, j, p.stderr


def verdict(rc):
    return "accept" if rc == 0 or 3 <= rc <= 6 else ("FAIL" if rc == 2 else "error")


def compare(rows, direction, name, mode, ours, oracle, want=None):
    (orc, oj, oerr), (mrc, mj, merr) = oracle, ours
    o_reason = oj.get("reason") if orc == 2 else None
    m_reason = mj.get("reason") if mrc == 2 else None
    diffs = []
    if orc != mrc:
        diffs.append(f"exit ours {mrc} vs oracle {orc}")
    if verdict(orc) != verdict(mrc):
        diffs.append(f"verdict ours {verdict(mrc)} vs oracle {verdict(orc)}")
    if o_reason != m_reason:
        diffs.append(f"reason ours {m_reason} vs oracle {o_reason}")
    if orc == 2 and mrc == 2 and oj.get("reason_code") != mj.get("reason_code"):
        diffs.append(f"reason_code ours {mj.get('reason_code')} vs oracle {oj.get('reason_code')}")
    if want is not None and mrc != want:
        diffs.append(f"ours {mrc} != reference expected {want}")
    if orc == 1 or mrc == 1:
        diffs.append(f"io/usage error: ours stderr={merr.strip()[:200]!r} oracle stderr={oerr.strip()[:200]!r}")
    key = (direction, name, mode)
    rows.append(dict(direction=direction, vector=name, mode=mode, ours=mrc, ours_reason=m_reason, oracle=orc,
                     oracle_reason=o_reason, diffs=diffs, expected_diff=EXPECTED_DIFF.get(key),
                     our_warnings=[w.get("code") for w in mj.get("warnings", [])], oracle_warnings=oj.get("warnings", [])))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--verifier", required=True)
    ap.add_argument("--gen", required=True)
    ap.add_argument("--harness", required=True)
    ap.add_argument("--workdir", required=True)
    a = ap.parse_args()
    bad = check_sums(a.harness)
    if bad:
        print("SHA256SUMS mismatch in the reference harness (not using it):", bad)
        return 1
    print("audit/harness SHA256SUMS: all entries OK")
    oracle = [sys.executable, "-B", os.path.join(a.harness, "audit_chain_naive_verify.py")]
    shutil.rmtree(a.workdir, ignore_errors=True)
    os.makedirs(a.workdir)
    rows = []

    # ---- (a) golden vectors -> our verifier
    V = os.path.join(a.harness, "vectors")
    E = json.load(open(os.path.join(V, "expected.json")))
    opub = os.path.join(a.workdir, "oracle_pubkeys.json")
    json.dump(E["pubkeys"], open(opub, "w"))
    mpub = os.path.join(a.workdir, "golden.pubkeys")
    with open(mpub, "w") as f:
        f.write("ct01-audit-pubkeys v1\n# Reference golden TEST key; vectors carry no DESIGN key ids -> unpinned\n")
        for e, pem in sorted(E["pubkeys"].items(), key=lambda kv: int(kv[0])):
            f.write(f"epoch={e} first=0 last=open key_id=unpinned pub={pem_to_sec1(pem)}\n")
    rt0 = os.path.join(a.workdir, "golden.rt0")
    open(rt0, "w").write(E["rt0"] + "\n")
    for name, cases in sorted(E["expect"].items()):
        vec = os.path.join(V, name + ".ac")
        chain_id = open(vec, "rb").read()[80:96].hex()
        for mode, want in sorted(cases.items()):
            if mode == "note":
                continue
            o_args = oracle + [vec, "--pubkeys", opub]
            m_args = [a.verifier, "--pubkeys", mpub]
            if "keyed" in mode:
                o_args += ["--epoch-key", "0:" + E["rt0"]]
                m_args += ["--epoch-key", "0:" + rt0]
            if "anchor" in mode:
                anc = E["anchor_successor"] if name == "successor" else E["anchor_clean"]
                o_args += ["--anchor", anc]
                m_args += ["--anchor", anc + ":" + chain_id]
            m_args += [vec]
            compare(rows, "a", name, mode, run(m_args), run(o_args), want)

    # ---- (b) our writer -> oracle
    W = os.path.join(a.workdir, "writer")
    os.makedirs(W)
    g = subprocess.run([a.gen, W], capture_output=True, text=True)
    if g.returncode != 0:
        print("gen_writer_chains failed:", g.stderr)
        return 1
    M = json.load(open(os.path.join(W, "manifest.json")))
    for name, m in sorted(M.items()):
        vec = os.path.join(W, name + ".ac")
        opj = os.path.join(W, name + ".oracle_pubkeys.json")
        json.dump({e: sec1_to_pem(h) for e, h in m["sec1"].items()}, open(opj, "w"))
        modes = ["public", "public+anchor"] + (["keyed", "keyed+anchor"] if m["tags"] else [])
        for mode in modes:
            o_args = oracle + [vec, "--pubkeys", opj]
            m_args = [a.verifier, "--pubkeys", os.path.join(W, name + ".pubkeys")]
            if "keyed" in mode:
                for e, rt in sorted(m["rt"].items()):
                    o_args += ["--epoch-key", f"{e}:{rt}"]
                    m_args += ["--epoch-key", f"{e}:" + os.path.join(W, f"{name}.rt{e}")]
            if "anchor" in mode:
                o_args += ["--anchor", f"{m['anchor_seq']}:{m['anchor_link']}"]
                m_args += ["--anchor", f"{m['anchor_seq']}:{m['anchor_link']}:{m['chain_id']}"]
            m_args += [vec]
            want = m["expect_keyed_anchor"] if mode == "keyed+anchor" else (m["expect_public"] if mode == "public" else None)
            compare(rows, "b", name, mode, run(m_args), run(o_args), want if want is not None and want >= 0 else None)

    unexpected = stale = 0
    for r in rows:
        status = "OK  "
        if r["diffs"] and r["expected_diff"]:
            status = "XDIF"
        elif r["diffs"]:
            status = "DIFF"; unexpected += 1
        elif r["expected_diff"]:
            status = "STAL"; stale += 1
        print(f"{status} ({r['direction']}) {r['vector']:<36} {r['mode']:<14} ours {r['ours']} {r['ours_reason'] or '':<16}"
              f" oracle {r['oracle']} {r['oracle_reason'] or '':<16} {'; '.join(r['diffs'])}")
        if r["our_warnings"] or r["oracle_warnings"]:
            print(f"       warnings ours={r['our_warnings']} oracle={r['oracle_warnings']}")
    na = sum(r["direction"] == "a" for r in rows)
    print(f"runs: {len(rows)} ((a) {na} golden, (b) {len(rows) - na} writer); unexpected differences: {unexpected}; stale allowances: {stale}")
    json.dump(rows, open(os.path.join(a.workdir, "oracle_diff.json"), "w"), indent=1)
    return 1 if unexpected or stale else 0


if __name__ == "__main__":
    sys.exit(main())
