# audit_chain (M1 beta): verifier, schema and writer library

**Beta:** this is a public beta of the CT-01 `audit_chain` library and offline verifier. It is **not for real PHI, production, or pilot use.** Synthetic data and TEST-ONLY software keys only. It is **not tamper-evident-certified** and makes no 45 CFR 164.312 claim.

This beta **implements DESIGN v0.3.4** (record bytes frozen at v0.3.3). The DESIGN.md in this tree is the v0.3.5 text. The following v0.3.5 rules are **not yet implemented**: M1 rulings 0, 1, 3, 4 and 7, and F73, F74 and F75 (see DESIGN §4.1, §4.2 and §6.2).

Milestone M1: the offline verifier `ct01_audit_verify`, the record schema, and a writer library. Successor, recovery and digest-failure writer logic, the ACK path, and the device daemon are out of scope.

## Layout
| Path | What |
|---|---|
| include/ct01/audit_record_layout.hpp | THE single layout header: sizes, offsets, labels, masks, per-code field rules |
| include/ct01/codes.hpp | GENERATED (tests/tools/gen_codes.py) from tests/spec/codes_tables_v0_3_4.py, checked against DESIGN Appendix A |
| audit_crypto | OpenSSL 3 libcrypto: SHA-256, HMAC, HKDF, CRC-32, P-256 verify, TEST-ONLY signer |
| audit_record | encode/decode, link/tag/signature pre-images, d_agg, tpmrec, context-free field rules |
| audit_result | exit codes 0-6 (7-9 reserved, never emitted) and `exit_code_for()`, the one precedence function |
| audit_inputs | `--pubkeys` (the ONLY key source), `--anchor`, `--epoch-key` parsers |
| audit_verify | `verify_chain()`, shared by the CLI and `device_self_check()` |
| audit_json | report JSON and JSONL export |
| audit_writer | memory and segment-file sinks, genesis/event/checkpoint/rotation |
| tools/ct01_audit_verify.cpp | CLI |

## CLI
`ct01_audit_verify --pubkeys FILE [--anchor SEQ:LINK:CHAIN_ID] [--epoch-key E:FILE]... [--export-jsonl] CHAIN_FILE...`

`--pubkeys` format (strict; no env vars, no default paths, no embedded keys):
```
ct01-audit-pubkeys v1
epoch=0 first=0 last=<u64|open> key_id=<64 hex|unpinned> pub=<130 hex SEC1 uncompressed>
```
`key_id=unpinned` turns off the key-id claim checks for that epoch and adds one warning per epoch. It exists only
for reference test vectors that carry no DESIGN key ids. `--checkpoints` and `--allowlist` exit 1 (M3/M4).

## Build and test
Point `CT01_OPENSSL_ROOT` at an OpenSSL 3 prefix (libcrypto). For a clang libFuzzer build, set `CT01_CLANGXX` to that compiler.

```
cmake -S . -B build-rel -G Ninja -DOPENSSL_ROOT_DIR=$CT01_OPENSSL_ROOT && ninja -C build-rel && (cd build-rel && ctest)
cmake -S . -B build-asan -G Ninja -DAUDIT_SANITIZE=ON -DOPENSSL_ROOT_DIR=$CT01_OPENSSL_ROOT ...
cmake -S . -B build-fuzz-clang -G Ninja -DCMAKE_CXX_COMPILER=$CT01_CLANGXX -DAUDIT_SANITIZE=ON -DAUDIT_FUZZ=ON -DOPENSSL_ROOT_DIR=$CT01_OPENSSL_ROOT ...
```

CTest runs:
- `audit_unit_tests` (doctest);
- `codes_vs_design`;
- `layout_vs_spec`;
- `oracle_differential` (needs `/usr/bin/python3` with `cryptography` and a reference harness; it is skipped otherwise);
- the fuzz driver replays;
- with `AUDIT_FUZZ`, libFuzzer smoke runs (the scratch dir comes first, so the seeds are never written).

## Decisions, differences from DESIGN v0.3.5, and known limits
**Implemented in this beta (DESIGN v0.3.4):**
1. **Forward-seq E and 66.** Only a level-4 66 (reason audit_space) moves E, to `subj_last+1`. Other 66 reasons neither FAIL nor move E. This affects warnings only, except that a level-4 66 which does not cover a hole still FAILs (`e_gap_range`).
2. **Pruned starts.** These are allowed only with an anchor at or above the first seq. `d_agg`, 69, 71 and ladder checks that reach before the first record become warnings (`*_unchecked_pruned`).
3. **EPOCH_START tag.** It is tagged with `K_{e+1}`, which needs `--epoch-key e+1` (§3.4 step 3).
4. **JSONL.**
    - It omits every `digest` field, tags and raw bytes.
    - It includes link, prev_link, sig, reason numbers and names, `d_agg` (CHECKPOINT only) and GENESIS `pred_fail_reason`.
    - JSONL is a non-verifying export view; links, tags and signatures are verified only from binary segments.
5. **Appendix A names.** 68 `recv_coverage` and 74 `lockdown` follow Appendix A.
6. **Not checked:**
   - `gaps_total`/`recoveries_total` against the sums of 66/64 records;
   - 73 count == provisioned NV handle (no input for it);
   - 64 `subj_last` semantics;
   - `e_nv_*` (device only);
   - `--allowlist` / GENESIS `d_agg`;
   - `--checkpoints` / fork (M3).

**Not yet implemented (DESIGN v0.3.5 text; not in this beta's code):**
- **Check order (ruling 0).** This beta uses field-before-tag order: length, structure, CRC, fields, seq/epoch, link, then tag and signature. DESIGN v0.3.5 §6.2 requires authenticate-first. A body bit-flip (`neg_bitflip_body`) therefore reports `e_field` 11 rather than the required `e_tag` 17; both are exit 2.
- **Key ids (ruling 1).** Test keys use SHA-256 of the SEC1 uncompressed point, and `--pubkeys` supplies the id used for verification. Reference test vectors that omit DESIGN key ids run with `key_id=unpinned`. A key-id prefix mismatch is labelled `e_genesis` in this beta; v0.3.5 requires `e_sig`.
- **Missing next-epoch key (ruling 3).** An `EPOCH_START` whose next-epoch key is absent from `--pubkeys` is labelled `e_epoch_handover` in this beta; v0.3.5 requires `e_sig`.
- **71 reason vs count (ruling 4).** A saturation mismatch is labelled `e_tpmrec` in this beta; v0.3.5 requires `e_reason` 6, and reason `saturated` holds if and only if `count == 2^32-1`.
- **CHECKPOINT reason 9 (ruling 7).** A CHECKPOINT with reason 9 without level 4 is accepted (exit 4) in this beta; v0.3.5 requires `e_level` 39 (FAIL).
- **Reseed (F73).** A valid staff-authorized reseed (record 22, actor_class 3) FAILs in this beta; v0.3.5 requires a FAULT, exit 6, and `gaps_total` incremented by 1.
- **Unexplained forward-seq jump (F74).** `fwd_seq_jump` exits 0, 4 or 5 in this beta; v0.3.5 requires exit 6.
- **Level-4 66 high end (F75).** A high-end gap in a level-4 66 range is accepted (exit 6) in this beta; v0.3.5 requires `e_gap_range` (FAIL, exit 2).

**Known limits:**
- Test private keys are public in the test tree, and `TestOnlyP256Signer` is compiled into the shipped library.
- Key material is not wiped from memory.
- The CLI does not catch exceptions, so it aborts instead of exiting 1.
- `--export-jsonl` prints records from a chain that later FAILs. JSONL is a non-verifying export view.
- Public (no `--epoch-key`) mode cannot check tags. A tail cut without an anchor, or an unsigned tail, is exit 5. A pruned prefix with an anchor can be accepted (exit 0, with a `pruned_start` warning).
- Not tamper-evident-certified. Synthetic data only. Not for real PHI, production, or pilot use. No tamper-evident claim before M4 GO.

## Third-party
- tests/third_party/doctest: doctest 2.4.11, MIT (LICENSE.txt), vendored.
- OpenSSL 3 (libcrypto) is a build dependency and is not vendored.
