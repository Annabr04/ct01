# audit_chain (M1 beta): verifier, schema and writer library

**Beta:** this is a public beta of the CT-01 `audit_chain` library and offline verifier. It is **not for real PHI, production, or pilot use.** Synthetic data and TEST-ONLY software keys only.

Ships DESIGN.md v0.3.5 (text-only relative to v0.3.4; record bytes frozen at v0.3.3) with the M1 code that passed its test suite against the v0.3.4 implementation. Milestone M1: the offline verifier `ct01_audit_verify`, the record schema, and a writer library. Successor, recovery and digest-failure writer logic, the ACK path, and the device daemon are out of scope.

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

## Decisions and open questions
1. **Key ids.** Test keys use SHA-256 of the SEC1 uncompressed point, and `--pubkeys` supplies the id used for verification. Reference test vectors that omit DESIGN key ids run with `key_id=unpinned`.
2. **Forward-seq E and 66.** Only a level-4 66 (reason audit_space) moves E, to `subj_last+1`. Other 66 reasons neither FAIL nor move E. This affects warnings only, except that a level-4 66 which does not cover a hole still FAILs (`e_gap_range`).
3. **Missing next-epoch key.** An `EPOCH_START` whose `S_{e+1}` is absent from `--pubkeys` gives `e_sig`. A key-id mismatch gives `e_epoch_handover`.
4. **71 reason vs count.** Reason `saturated` holds if and only if `count == 2^32-1`.
5. **Check order.** This beta follows the field-before-tag order in DESIGN §6.2 as written for the M1 implementation: length, structure, CRC, fields, seq/epoch, link, then tag and signature.
6. **Not checked:**
   - `gaps_total`/`recoveries_total` against the sums of 66/64 records;
   - 73 count == provisioned NV handle (no input for it);
   - CHECKPOINT reason 9 requiring level 4 (noted in DESIGN v0.3.5; not enforced in this beta code);
   - 64 `subj_last` semantics;
   - `e_nv_*` (device only);
   - `--allowlist` / GENESIS `d_agg`;
   - `--checkpoints` / fork (M3).
7. **Pruned starts.** These are allowed only with an anchor at or above the first seq. `d_agg`, 69, 71 and ladder checks that reach before the first record become warnings (`*_unchecked_pruned`).
8. **EPOCH_START tag.** It is tagged with `K_{e+1}`, which needs `--epoch-key e+1` (§3.4 step 3).
9. **JSONL.**
    - It omits every `digest` field, tags and raw bytes.
    - It includes link, prev_link, sig, reason numbers and names, `d_agg` (CHECKPOINT only) and GENESIS `pred_fail_reason`.
    - JSONL is a non-verifying export view; links, tags and signatures are verified only from binary segments.
10. **Appendix A names.** 68 `recv_coverage` and 74 `lockdown` follow Appendix A.

## Third-party
- tests/third_party/doctest: doctest 2.4.11, MIT (LICENSE.txt), vendored.
- OpenSSL 3 (libcrypto) is a build dependency and is not vendored.
