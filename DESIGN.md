# audit_chain: keyed, checkpointed audit chain for CT-01 (DESIGN v0.3.5)
Code, files, CMake targets and identifiers use the plain name `audit_chain`.
v0.3.5 (2026-11-11 ET): TEXT-ONLY. CT-01 rulings on the M1 implementation questions (0-7, normative, marked "M1 ruling") and review
A012 (F66/F70/F71/F67 closed; new F73 MEDIUM, F74-F77 LOW) folded in. Zero byte change (tests/spec/layout_v0_3_5.py asserts every offset equals
v0.3.4); codes tables append-only (tests/spec/codes_tables_v0_3_5.py asserts numbers and names equal v0.3.4). Supersedes v0.3.4.
v0.3.4 (2026-11-11 ET): TEXT-ONLY revision for review A011 (v0.3.3: SCHEMA CAN FREEZE with conditions; MEDIUM F66, F70, F71; LOW F67-F69,
F72). NO byte, offset or size change (tests/spec/layout_v0_3_4.py asserts every offset equals v0.3.3: 144/180/216/316). Adds the frozen numeric
tables (Appendix A, codes.hpp; tests/spec/codes_tables_v0_3_4.py), one d_agg rule, the corrected contiguity rule and the level-4 entry
ordering. Supersedes v0.3.3.
v0.3.3 (2026-11-11 ET): Review A009 (on v0.3.1: PASS WITH CONDITIONS, MEDIUM F47-F52, LOW F53-F58) and A010 (v0.3.2 diff-check: PASS WITH
CONDITIONS, MEDIUM F59-F63, LOW F64-F65) folded in. Schema
CHANGE for F60: SIGNED 308 -> 316 B (dfail_total u32 + ext_reserved u32); EVENT stays 180 B. Layout: tests/spec/layout_v0_3_3.py. Traceability
§14 (A009/A010 rows). Supersedes v0.3.2.
v0.3.2 (2026-11-11 ET): joint rulings C5 (audit-storage ladder REPLACES C1 backpressure; ACKs never stop for audit storage; GAP bounds),
C6 (commissioning-gated lockdown behaviour, NV_commissioned bit) and C7 (KEYED_FAILED + TPM-recovery record), folded in and closed
2026-11-11. C1-C7 all ruled; only Q7 open. Supersedes v0.3.1.
v0.3.1 (2026-11-11 ET): C1 (durability barrier, dedicated log filesystem, watermark backpressure) and C2 (per-boot
platform lockdown) folded in and closed; new §5.6 reconciles the C1 watermark with HIPAA Q6 (verdict: CONFLICT, open item C5); new
clarification C6 (phEnable refuse-to-start vs G7). C3 (transfer totals, timestamp granularity) and C4
(explicit digest method, genesis-recorded mode, TPM-only digest key) folded in and closed; layout: tests/spec/layout_v0_3_1.py (sizes unchanged).
v0.3 (2026-11-11 ET): Review A008 (v0.2 PASS WITH CONDITIONS; new MEDIUM F39-F41, LOW F42-F46, exit-code conditions) fixed in the text;
rulings (Q1-Q4, Q11-Q14, F45, sessions) and decisions (Q2, Q5, Q6, Q8, Q9, Q10, Q12),
2026-11-11, folded in and marked where used. Supersedes v0.2; earlier: v0.1, v0.1-A007p1. Traceability: §14. Layout: tests/spec/layout_v0_3.py (v0_2 kept).
Author: CT-01 Scrum Master. Status: PROPOSED v0.3.5 (schema FROZEN per A011; A012 freeze stands), for design closure check before M1. Nothing implemented; nothing measured on target
hardware; every cost or rate is UNMEASURED unless it cites a file; arithmetic is marked as arithmetic.
NO PILOT USE AND NO "TAMPER-EVIDENT" CLAIM BEFORE M4 GO (A008 §5 condition). No 45 CFR 164.312 compliance claim (§10).
Sources: CT-01 design documents (HIPAA checklist §4; ADR-002 key-encryption hardware; encryption key management; data map; daemon notes) and the existing device implementation of the sealed delivery log and TPM unseal path, used as read-only context for this design.
Rules: synthetic data only; no edits to the CT-01 device tree; new tree for audit_chain sources and tests; no frame, CT1F, recvlog-1 or
ct01.h change; off by default UNTIL a device is provisioned (§6.1).

## 0. What exists today (facts, cited)
- The current CT-01 audit files are plain-text, append-only, and metadata-only; they are not integrity-protected, and write results are not always checked. This design covers that gap for events the device emits.
- The existing sealed delivery log (recvlog-1) provides confidentiality and sequence checks, but it is not an external tamper-evident anchor for the audit chain.
- The existing TPM key-unseal path must not be reused by audit_chain. audit_chain requires salted, parameter-encrypted HMAC sessions and the key templates in §3.1. ADR-002 remains Proposed.
- Gap: a tamper-evident audit log and SIEM export remain required before pilot (HIPAA checklist). Earlier "no audit log in code" checklist items were stale; the audit-log item is now marked PARTIAL. CLOSED for this doc.
- No holder transport exists yet (no TLS). A transport-auth ADR (TLS + VOID auth) is scheduled for M4, before pilot. Mutual TLS 1.3 is preferred, 1.2 minimum, with pinned holder certificates, before pilot.

## 1. Threat model (first)
Assets: ORDER, COMPLETENESS and CONTENT of audit events. Never payload: no payload, no patient_ref, no unkeyed function of payload bytes, no
exact per-frame length (Q9), no patient-linkable id in clear (Q10).
Attackers:
- A1 (storage): reads/rewrites all stored files and key blobs at any time, keeps copies, restores old blobs; no TPM access (not root, not in
  group tss). Recomputes any unkeyed hash. Can edit config files (incl. `audit_chain=off`, §6.1).
- A2 (live window [t0, t1]): A1 + TPM use as the service account (root or group tss = A2): unseal, use loaded keys, read memory; cannot
  extract fixedTPM private keys. Physical attacker = A2 today (no PCR binding, no secure boot; ADR-002 §5.5).
- Platform hierarchy (A008 F45; Ruling 2026-11-11): treat platformAuth as likely EMPTY on the Pi (no
  firmware takes the platform hierarchy), so A2 could e.g. TPM2_Clear (destroys chain keys and NV: DoS + forced chain replacement). Fix in §3.1.
  A009 F53: the reference TPM SETs phEnable on EVERY TPM2_Startup (CLEAR and STATE), so from Startup until the lockdown the platform
  hierarchy is open (empty auth after CLEAR; after a resume only a random platformAuth set earlier protects it). A009/A010 F50: TPM2_Clear
  (via an unset lockoutAuth or the boot window) deletes NV_epoch and NV_commissioned: fixed by §3.1 (random ownerAuth/lockoutAuth,
  ClearControl(disableClear), NV name checks, Release never honours `off`).
- Insiders: group tss / host admin = A2; fleet-service admin can delete held checkpoints (the second holder is the only check, §6.3);
  CT-01 as supplier of the key list (reviewers who do not trust CT-01 need EK/AK evidence from the vendor CA). Escrow holder: REMOVED (Q2, §3.2).
Out of scope: TPM silicon; a compromised verifier; compromise of BOTH holders; attacks on the SIEM; preventing deletion (we detect where §6.3 allows).
Goals (tests in §8):
G1 Changes before the last verified record detected (bit-flip, edit, reorder, splice, duplicate, middle deletion).
G2 Recomputation without keys detected (unkeyed recompute and wrong-key MACs fail).
G3 Tail truncation, rollback and whole-chain replacement detected when a holder has a newer checkpoint (from M4), or on the device at NV_export
   granularity (from M2: at most hourly bumps, §3.5). Without either: undetected; outputs say `anchor: none`.
G4 kill -9 at any point leaves a verifiable prefix; every returned append is in it.
G5 Public verification with keys whose trust comes from TPM2_Certify + EK chain, never from the chain.
G6 No unkeyed ePHI function, no exact per-frame length, no patient-linkable id in clear.
G7 (A008 F41; Decision 2026-11-11, Q6) The audit chain never halts clinical delivery: a chain FAIL or a
   missing chain opens a signed successor chain and latches FAULT; delivery continues.
Honest limits:
- Nothing proven about records written during [t0, t1]; A2 can rewrite everything not covered by a checkpoint a holder received before t0.
- Copied unsealed bytes of R^t_e allow tag forgery for epoch e after t1 (PolicyNV revokes blob reuse, not byte reuse). The digest key never
  leaves the TPM (Q5, §3.1), so it cannot be copied, only used during [t0, t1].
- Torn tail = arbitrary tail truncation against A1 (stub rule bounds the stub, not the loss). A008 S3b: before a holder holds the recovery
  checkpoint, A1 can cut back to just before event 64 and erase the recovery trace; the on-device NV_export (§3.5) and the signed
  recoveries_total (§4.1) narrow this only to records after the last NV bump. Stated limit until M2. From M2 (A009 F57) the recovery
  CHECKPOINT ALWAYS bumps NV_export (no hourly cap), so cutting back before event 64 removes the bump checkpoint and the device reports
  e_nv_regress (§3.5): S3b is closed ON THE DEVICE from M2. Off device without a holder it remains undetected (exit 4).
- Before M4 there is no holder: G3 holds only on device and only at NV granularity (from M2); no successor genesis can reference a holder
  checkpoint (§6.1 marks it predecessor_unknown).
- Undetected persistent A2 (no secure boot) can forge all future records with genuine keys. Secure boot + re-imaging are prerequisites.
- Media corruption and tampering are indistinguishable (both FAIL).
- Time (A008 F43): ts_ms, mono_ms and the tpm_clock fields are WRITER-REPORTED (copied from TPM2_ReadClock, not attested); A2 can write any
  value; the TPM clock can step back after a non-orderly shutdown (`safe` = 0, recorded in sflags). Only holder receipt time is trusted.
  Attested time (TPM2_GetTime by the AK) is an M2 measurement option, not in the design.
- Events the code never emits (admin logins, pairing, config changes, firmware updates) are not covered.
Assumptions: audit_chain's own TPM code meets §3.1 (M2 gate); secure boot for claims beyond A2-as-physical; OpenSSL; one writer per chain.
Read-only rootfs (A009 F58): binaries, systemd units, the compiled-in defaults and the staff-uid allowlist live on a read-only (pilot:
dm-verity) root filesystem. If the rootfs is writable, A1 + a reboot = A2 (and gains the F53 boot window); the design then claims nothing
beyond A2. One forward stream per chain (one ct01d peer per ct01_recv in v1) is assumed by the §6.2 seq-continuity checks; multi-peer
receivers need per-peer ranges (deferred, not in v1).

## 2. HMAC chain vs signed periodic heads vs hybrid
| Property | (a) HMAC chain | (b) hash chain + signed heads | (c) HYBRID (chosen) |
|---|---|---|---|
| Verifier needs | symmetric key (can forge) | public key | public keys; tail tags verified on the device only (no escrow, Q2) |
| A1 recompute without keys | detected | after the last head: not detected | detected (tags on device; heads need the TPM key) |
| Tail truncation / rollback | not without holder | not without holder | holders (M4); NV_export on device (M2) |
| Survives A2 | no | heads received before t0 | checkpoints received by a holder before t0 |
| TPM ops | 0 per record | 1 Sign per head | 1 Sign per checkpoint; 1 TPM2_HMAC per digest-bearing event (Q5, §3.1); NV_Increment <= 1/h |
| CPU per record | SHA-256 + HMAC (unmeasured) | SHA-256 | SHA-256 + HMAC (unmeasured) |
Cadence (A007 F34): a CHECKPOINT within 10 s of the FIRST uncheckpointed record, or at 256 uncheckpointed records, whichever first; also on
shutdown, before export, after recovery, at chain creation and around EPOCH_START; NO idle checkpoints. Each is exported to BOTH holders
(Ruling 2026-11-11, Q1: fleet service + SIEM over mutual TLS) when the link is up, queued otherwise.
Per-record TPM2_Sign stays rejected (unmeasured vs the 20 ms / 32-frame group budget, recv_log.hpp:47-49). The per-event TPM2_HMAC for
digests (Q5) is ONE command per recv group (<= 50 groups/s at full rate, arithmetic from a007 layout_check.log); its latency is UNMEASURED
(swtpm in M2, hardware in M5). If it does not fit the M4 gate, the Q5 fallback applies (dmode 2 ABSENT, set at the next epoch or successor; seq + bucketed length; §4.3).
TPM latency, honest consequence (A009 §3(a); NOT measured by us): published ECDSA P-256 TPM2_Sign figures are 68.9 ms (SLB9670), 35.6 ms
(SLB9672) and 25.3 ms (ST33KTPM2XSPI) (wolfTPM benchmarks as cited by A009); no published TPM2_HMAC figure for the target parts ("somewhat
better" than Sign per a 2024 PC-TPM survey cited by A009), and salted, encrypted sessions (required, §3.1) add cost. The budget is 20 ms per
group at <= 50 groups/s (recv_log.hpp:47-49). The TPM executes one command at a time, so a checkpoint Sign (25-69 ms) stalls every queued
HMAC. If TPM2_HMAC is near or above 20 ms, one HMAC per group blows the group budget and the Q11 throughput gates fail with audit on.
Options (all UNMEASURED; NOT decided here; open question C8 for the CT-01):
(O1) batch the digest HMAC: keep each group's inner hash in locked RAM and run ONE TPM2_HMAC over the inner hashes of all groups that share
     one durability barrier (groups queued while the TPM is busy commit together); needs dmethod 5 (reserved in §4.1 now, FAIL in v1).
(O2) take checkpoint signing off the ACK path: Sign runs asynchronously and is scheduled between HMACs; cadence (10 s) stretches under load;
     does not help if HMAC alone exceeds the budget.
(O3) the ruled C4 fallback: dmode 2 (digest ABSENT), explicit at the next epoch or successor, never a runtime switch.
(not an option) moving D_e into host RAM: excluded by C4 condition 3.
M5 GO/NO-GO (explicit): on the target TPM with salted, encrypted sessions, at 50 groups/s with checkpoint signing running, measure TPM2_HMAC
and TPM2_Sign p50/p99 and the audit share of the group latency. GO for dmode 1 with one HMAC per group only if p99 group latency stays
within the 20 ms budget AND the Q11 gates hold; otherwise NO-GO for that configuration and the owners pick O1, O2 or O3 (C8).

## 3. Key management on the ADR-002 path
### 3.1 Keys and TPM objects
| Key / object | What | Where | Used for |
|---|---|---|---|
| R^t_e (tag root) | 32 random bytes, sealed keyedHash | TPM, blob `audit_chain/troot_<e>.tpm` | HKDF -> K_e |
| K_e = HKDF-SHA256(salt=chain_id, IKM=R^t_e, info="ct01.audit_chain.v1.epoch_key" ‖ u32le(e), L=32) | tag key | LockedBytes, wiped on close/rotate/error | record tags |
| D_e (digest key; Q5) | keyedHash HMAC key (sign=1, decrypt=0, scheme HMAC-SHA256), fixedTPM, fixedParent, sensitiveDataOrigin, userWithAuth=0, noDA (A009 F52: high-entropy auth; a tss-group process cannot force failures via DA lockout); created per epoch, independent of R^t_e | TPM, blob `audit_chain/dkey_<e>.tpm`; NEVER leaves the TPM, never escrowed, never given to a holder or SIEM | TPM2_HMAC for grp/act digests (§4.3) |
| S_e (checkpoint signing key) | ECDSA P-256; sign=1, decrypt=0, restricted=0, fixedTPM, fixedParent, sensitiveDataOrigin, userWithAuth=0, adminWithPolicy=1, noDA (F52), scheme fixed ECDSA/SHA-256 | TPM child of the SRK, blob `audit_chain/sign_<e>.tpm` | TPM2_Sign over SHA-256(DS_CKPT ‖ h) only |
| AK | restricted signing key; MANDATORY at provisioning, EK-certified via MakeCredential/ActivateCredential | TPM | TPM2_Certify of every S_e and D_e; never used for anything else; S_e is never the AK |
| NV_epoch, NV_export | NV indices, TPMA_NV_COUNTER, NOT TPMA_NV_ORDERLY | TPM NV | epoch index (in every key policy); on-device anchor (§3.5) |
Rulings 2026-11-11:
- Q3 (CLOSED, YES with conditions): S_e is sign-only (no decrypt), fixedTPM/fixedParent; policy PolicyCommandCode(TPM2_Sign) AND auth
  (PolicySecret / authValue) [AND PolicyNV(NV_epoch == e), §3.4]. Every signed message is the fixed 56-byte pre-image DS_CKPT ‖ h
  (24 + 32 B; checked in layout_v0_3.py), so it begins with ASCII "c" (0x63) and can never parse as a TPMS_ATTEST (which begins with
  TPM_GENERATED_VALUE, first byte 0xff). S_e is separate from the AK and never reused for any other purpose.
- Q13 (CLOSED, YES): AK mandatory at provisioning, EK-certified via credential activation; until hardware arrives, an swtpm EK CA (TEST-ONLY,
  never accepted by a production holder). M2 gate.
- Q14 (CLOSED): counters non-ORDERLY (an orderly counter may jump forward after a non-orderly shutdown, A008 N4); NV handles from the TCG
  owner-defined range, recorded in an ADR (to be written; this doc does not pick handle values); bumps per checkpoint
  (NV_export) and per epoch (NV_epoch), at most once an hour; TPM datasheet endurance checked before M4 (no measured figure exists).
- Sessions (CLOSED as a requirement): Unseal (R^t_e) and Sign (S_e), and also TPM2_HMAC (D_e) and NV writes, run in HMAC sessions SALTED to the
  SRK with parameter encryption (AES-CFB) before pilot. Sign has its own policy (above), because ADR-002 §5.5 covers Unseal only. Policies:
  R^t_e: PolicyCommandCode(TPM2_Unseal) AND auth AND PolicyNV(NV_epoch == e). D_e: PolicyCommandCode(TPM2_HMAC) AND auth AND PolicyNV(NV_epoch == e).
- F45 / C2 (CLOSED). Ruling 2026-11-11 (F45): treat platformAuth as likely empty; lock the platform
  hierarchy. Ruling 2026-11-11 (C2, AGREED): the lockdown runs on EVERY boot as an early systemd oneshot
  (`ct01-tpm-lockdown.service`, plain name), ordered before networking and before ct01d; it PREFERS TPM2_HierarchyControl(TPM_RH_PLATFORM,
  enable=TPM_RH_PLATFORM, state=NO) (phEnable := 0) over setting a random platformAuth. A Release ct01d reads TPM_PT_STARTUP_CLEAR
  (TPM2_GetCapability) and requires phEnable == 0; what happens otherwise depends on commissioning (C6 ruling below). TPM firmware updates go
  through an explicit maintenance-mode boot that skips the lockdown and does not start ct01d. Verified on swtpm at M2 for a power cycle
  (TPM2_Startup(CLEAR)) and a resume (TPM2_Startup(STATE)), on hardware at M5.
  Spec check (not fully confirmed):
  * TCG TPM 2.0 Library Part 1: Architecture (v1.85 copy read 2026-11-11 at iommu.com/datasheets/tpm/TPM-2.0-Library-v185-Part-1-Architecture.pdf,
    platform-controls text following clause 10.2 "Controls"): "On any _TPM_Init, phEnable is SET ... When phEnable is CLEAR, a _TPM_Init is
    required to SET it" and "On TPM Reset or TPM Restart, platformAuth is set to an EmptyAuth, and platformPolicy is set to an Empty Policy."
  * Part 2: Structures, clause 9.7 TPMA_STARTUP_CLEAR (Table 35, bit 0 phEnable; ISO/IEC 11889-2 sample): "These attributes are set to their
    default state on reset on each TPM Reset or TPM Restart. The attributes are preserved on TPM Resume. On each TPM2_Startup(TPM_SU_CLEAR), the
    TPM will set these attributes to their indicated defaults."
  * CORRECTION (A009 F53, credited to review A009, evidence from the Microsoft TPM 2.0 reference Hierarchy.c and c2_phEnable notes): the TCG /
    Microsoft reference implementation's HierarchyStartup() sets phEnable = TRUE on EVERY TPM2_Startup, including STATE (resume), and resets
    platformAuth/platformPolicy only when the startup is NOT a resume. The v0.3.1/v0.3.2 reading ("resume suggests phEnable returns to its
    pre-suspend value") was WRONG for the reference code, and so was the brief's premise that Startup(STATE) preserves phEnable. Re-running
    the lockdown on resume is therefore REQUIRED, not belt-and-braces. Hardware TPMs are expected to follow the reference; verified on
    swtpm at M2 and on the target part at M5.
  * Lockdown sequence (A009 F53; supersedes the C2 "prefer HierarchyControl over a random auth": both are now done, auth first; Engineering
    acknowledgement requested as C11): (1) TPM2_HierarchyChangeAuth(TPM_RH_PLATFORM, 32 random bytes, discarded) THEN (2)
    TPM2_HierarchyControl(enable=TPM_RH_PLATFORM, state=NO). Run on EVERY boot and EVERY resume: the oneshot is ordered before any non-root
    unit and before networking; /dev/tpm0 is root-only (/dev/tpmrm0 group tss = A2 by definition); ct01d also applies the sequence itself at
    start, after resume and when its periodic phEnable re-check (PROPOSED every 60 s) finds phEnable == 1 with an empty platformAuth. The
    random platformAuth survives a resume, which closes the resume window that HierarchyControl alone leaves (phEnable is SET again by Startup).
    If HierarchyControl fails, ct01d still sets the random platformAuth (A010 F63) before entering C6 rule 2.
- C6 (CLOSED). Joint ruling, 2026-11-11 (replaces the v0.3.1 C6 text):
  1. Before commissioning (lockdown never verified on this device): kek_unavailable pattern (CT01D.md:178): process up, /status FAULT
     `lockdown_unverified`, every ingest 'F', nothing buffered. Commissioning blocks go-live until the lockdown is verified.
  2. After commissioning, if the per-boot (or post-resume) lockdown or the phEnable check fails (e.g. a reboot on the ward): keep delivering,
     latch FAULT `lockdown_failed` (record 74), raise the off-box alarm (both holders + SIEM), retry with backoff (PROPOSED 1 s doubling to
     15 min), and BLOCK new seals (TPM2_Create of sealed objects: K_e blobs, buffer KEK re-seal), AK enrollment (credential activation) and
     epoch rotation (§3.4) until it succeeds (record 74 reason `restored`). Checkpoint signing and existing Unseal continue.
  HIPAA conditions: no plaintext and no software-key fallback (the buffer stays TPM-KEK encrypted; if Unseal itself fails, kek_unavailable
  applies as today; DEV software keys stay refused in Release); a lockdown failure open > 24 h goes to incident review (holder alarm).
  How the device knows "commissioned / lockdown verified at least once": the AUTHORITY is a TPM NV bit; a chain record corroborates it.
  * `NV_commissioned`: TPM_NT_BITS index, owner-defined handle from the Q14 ADR, non-ORDERLY; TPMA_NV_POLICYWRITE only (no OWNERWRITE or
    AUTHWRITE), read by ct01d at start and after resume. authPolicy = PolicyCommandCode(TPM2_NV_SetBits) AND PolicySigned(K_comm) with the
    TPM nonce and a cpHash bound to bit 0, where K_comm is the commissioning key held by the Biomed/fleet commissioning service, never on
    the device. Bit 0 is set once, at the commissioning ceremony, after a fresh Startup(CLEAR) showed phEnable == 0.
  * Chain record 73 `commissioning_verified` (export now; signed into the next CHECKPOINT): lockdown method, observed phEnable, NV_commissioned
    handle. Holders record that this chain_id belongs to a commissioned device.
  * Why deleting files cannot fake it: the state is not in a file. NV bits can only be SET (TPM2_NV_SetBits ORs), so the bit cannot be
    cleared; device root cannot SET it without a fresh K_comm signature over the TPM nonce. Deleting the chain or config leaves the bit
    (device stays "commissioned"; the chain goes the §5.4 successor path). Undefining the index needs ownerAuth; if root has it, the index
    vanishes, the device reverts to rule 1 (FAULT, all 'F'): a visible DoS, never a bypass, and holders alarm because the chain_id was
    recorded as commissioned. Residual: commissioning trusts the device's own GetCapability report of phEnable (not attested); the ceremony
    is on site. Unverified on swtpm; M2 gate.
  * Hardening (A010 F63, A009/A010 F50; M2 gate):
    - Provisioning sets ownerAuth and lockoutAuth to random 32-byte values (custody: two-person, recorded in the key ceremony, PROPOSED
      default; or discarded; to be decided, C10) and runs TPM2_ClearControl(disableClear = YES). With the platform hierarchy locked every
      boot, TPM2_Clear is then unavailable at runtime; re-enabling it needs the maintenance-mode boot (firmware/RMA only).
    - NV name check: ct01d reads TPM2_NV_ReadPublic for NV_commissioned, NV_epoch and NV_export and compares each NV Name (nameAlg ‖
      H(TPMS_NV_PUBLIC): attributes, authPolicy, dataSize) with the provisioned constants (read-only rootfs + inventory). A mismatch (e.g. a
      handle redefined with AUTHWRITE and empty auth) = the index is treated as ABSENT + FAULT `nv_tampered` + record 70 reason nv_tampered.
    - PolicySigned for NV_SetBits pinned: nonceTPM REQUIRED, expiration = 0 (this session only), cpHashA = H(TPM2_NV_SetBits(NV_commissioned,
      bits = 1)), policyRef = "ct01.commission" ‖ EK Name; the policy contains NO PolicyAuthValue / PolicyPassword. K_comm lives in an HSM with
      two-person use (fleet commissioning service).
    - Release builds NEVER honour `audit_chain=off` (§6.1): a missing NV_epoch in a Release build = FAULT `tpm_cleared` + successor GENESIS
      (reason tpm_cleared, predecessor_unknown semantics) with the F56 key set. Interaction with C6 rule 1 after a Clear on a commissioned
      device (NV_commissioned gone -> all 'F'): residual DoS lever, reachable only through the boot window or physical access once
      disableClear is set; question C9 (owners) whether a verified record 73 under the inventory S_0 key keeps rule 2.
  * Limit: a physical attacker who boots their own OS (no secure boot) simply skips the oneshot; this lockdown only removes the A2 platform
    lever on a CT-01-booted system.
Successor key set when the old keys are unusable (A009 F56): if S_e/D_e/R^t_e cannot be used (e_nv_epoch, deleted or policy-failing blobs,
after a Clear), the successor creates a FRESH key set (R^t, D, S) bound to PolicyNV(NV_epoch == current value; a re-defined NV_epoch after a
Clear starts at its new value), Certifies S and D by the AK, and signs the successor GENESIS with the new S. Holders and --pubkeys accept it only
via that Certify, pinned per (chain_id, epoch). AK unusable (Clear, lost blob): FAULT `ak_lost`, no signed successor is possible; the outage is
counted in the fixed-size gap counter file (§5.2, K_e-tagged if K_e is still usable) and exported as text/journald; delivery continues (G7,
subject to C6 rule 1 when NV_commissioned is also gone, C9); the device needs re-provisioning (AK enrolment).
Fail behaviour: a TPM/policy error at open never stops the daemon or delivery (G7): the daemon starts in FAULT (`audit_chain_unavailable`),
keeps the CT01D.md:178 status semantics for status, and records the outage as chain_gap when the chain opens again (§5.2). ESAPI only, no vendor
commands. Dev builds may use file roots + a software P-256 key + a software HMAC key, reported "audit_chain signer=file (DEV ONLY)"; refused
in Release; never accepted by a holder.

### 3.2 Custody (who holds what)
| Holder | Holds | Can |
|---|---|---|
| Device (ct01d, ct01_recv: one chain each) | blobs; K_e in RAM; D_e and S_e only inside the TPM | append, self-check, sign, digest |
| Provisioning inventory (two-person, ADR-002 §5.6) | EK cert + chain, AK public + activation record, S_0 public + Certify, chain_id(s), GENESIS link, staff-uid allowlist reference (§4.4) | source of S_0 trust |
| Public verifier | --pubkeys from inventory/holder Certify evidence only; exported checkpoints | verify links + signatures; cannot forge |
| Holders (fleet service AND customer SIEM; Q1) | every checkpoint (with d_agg, §4.3) + receipt time + pinned epoch ranges | anchor; fork/regression/replacement checks |
Escrow: REJECTED. Ruling and Decision 2026-11-11 (Q2): no escrow. Losing R^t_e costs MAC
(tag) verification on that device only; public checkpoint verification still works. The v0.2 keyed-verifier escrow path is removed. If escrow
is ever mandated: per-epoch keys only (never a root, never D_e), two-person control, recorded in the key ceremony. --epoch-key (§6.2) is
therefore TEST-ONLY and on-device only.

### 3.3 Epoch key trust (A007 F26)
- Keys are never learned from the chain. S_0 comes from the provisioning inventory. S_{e+1} enters --pubkeys / a holder's list only after
  TPM2_Certify(S_{e+1}) by the registered AK (qualifyingData = SHA-256("ct01.audit_chain.v1.certify" ‖ chain_id ‖ u32le(e+1) ‖ holder nonce)),
  with the certified Name matching the §3.1 template (attributes, fixed scheme, authPolicy incl. PolicyNV(NV_epoch == e+1)).
- Holders and --pubkeys pin each epoch's [first, last] seq; a signature by S_e after EPOCH_START(e+1) is e_epoch.
- Residual: an A2 can trigger a genuine rotation and copy R^t_{e+1} bytes (tag forgery for e+1 later), not S_{e+1} or D_{e+1}. Rotate after
  compromise only on a re-imaged device (§3.6). Undetected persistent A2 forges everything (§1).

### 3.4 Rotation (epochs) and its crash path (A008 F44)
An epoch = (R^t_e, D_e, S_e); e == NV_epoch. Rotate yearly with the KEK (ENCRYPTION_KEY_MGMT §5), on TPM/firmware change, after a suspected
compromise (re-imaged device only). Blob writes: tmp + fsync + rename + dir fsync.
1. Create R^t_{e+1} (its 32 bytes are generated in LockedBytes and KEPT there until step 5), D_{e+1}, S_{e+1}, all with PolicyNV(NV_epoch == e+1)
   (unusable now); Certify S_{e+1} and D_{e+1} by the AK.
2. Append CHECKPOINT (epoch e, S_e); export.
3. Append EPOCH_START (epoch e+1; tag with K_{e+1} from the RAM copy; digest = key id of S_{e+1}; signed by S_e as a claim); fsync.
4. TPM2_NV_Increment(NV_epoch) -> e+1. From here every epoch-e key fails policy, including restored blob copies (A007 F26).
5. Append CHECKPOINT (epoch e+1, S_{e+1}); export with Certify evidence; wipe the RAM copy of R^t_{e+1} only after this returns.
6. Old-epoch blobs (Ruling 2026-11-11, Q4, CLOSED): destroy only after BOTH holders ACK the step-5
   checkpoint. The 7-day cap stays, but reaching it without both ACKs raises an alarm and escalates (FAULT-class status + export); it never
   destroys silently. At the cap, destroy only if a signed checkpoint covering the old epoch was exported; otherwise keep the blobs and keep
   alarming. Deletion is hygiene; step 4 is the revocation.
Open-time crash path (explicit order):
- NV_epoch == e, no EPOCH_START(e+1): discard e+1 blobs; restart at step 1.
- NV_epoch == e, EPOCH_START(e+1) present and the last record: (i) verify its S_e signature and link (S_e still passes policy); (ii) if valid,
  TPM2_NV_Increment(NV_epoch); (iii) now unseal R^t_{e+1} and verify EPOCH_START's tag (it cannot be verified before (ii), because R^t_{e+1}
  only passes policy after the increment); (iv) tag invalid -> FAIL (successor chain, §5.4); valid -> step 5.
- NV_epoch == e+1: complete step 5 if missing; step 6 per its rule.
- NV_epoch > newest chain epoch + 1, or chain epoch > NV_epoch: FAIL e_nv_epoch (successor chain, FAULT).

### 3.5 On-device anchor: NV_export (A008 F39; evaluated on swtpm in M2; hardware endurance UNMEASURED until M5)
- Bump rule (Q14 ruling): at a CHECKPOINT, at most once per hour (the first checkpoint >= 1 h after the previous bump), INDEPENDENT of
  holders, so the anchor exists from M2. EXCEPTIONS, always bumped regardless of the hourly cap (A009 F57; rare, wear negligible): the
  recovery CHECKPOINT (§5.4), the successor chain's first CHECKPOINT, the first CHECKPOINT after config_mismatch (70) or nv_tampered, the first
  CHECKPOINT that sets sflags bit2 (digest_failed), and the level-4 entry CHECKPOINT (§5.6). Arithmetic (a008/layout_check): <= 8,760 bumps/yr, <= 87,600 over 10 years.
- Order (F39 fix): (holder_ack(s) for any received ACK, if present) -> append CHECKPOINT carrying nv_export = v+1 -> fsync -> TPM2_NV_Increment
  (v -> v+1). A1 cannot make the chain run ahead of the TPM, because that needs an S_e signature.
- Open rule: v_chain = nv_export of the newest signed record; v_tpm = NV_export. v_chain == v_tpm: OK. v_chain == v_tpm + 1: crash window,
  do the increment. Anything else: FAIL e_nv_regress (successor chain, FAULT; §5.4). (a008 model: N1' and N1'' pass, N2' fails.)
- (A009 F48; replaces the v0.3 definition, which held for every signed record) The BUMP CHECKPOINT is the signed record with nv_export == v_tpm
  (the record whose fsync preceded the last TPM2_NV_Increment). Open sequence, in this order: (1) verify the prefix up to the first failing
  record; (2) run the open rule ON THAT VERIFIED PREFIX: OK only if the bump checkpoint is in it (or v_chain == v_tpm + 1: crash window, do the
  increment); otherwise e_nv_regress -> FAIL -> §5.4 successor, NEVER recovery; (3) only then consider torn-tail recovery (§5.3/§5.4), which may
  never cut at or below the bump checkpoint or a holder-ACKed checkpoint (holder_ack in the verified prefix). "Counter-acknowledged" in older
  text means "at or below the bump checkpoint".
- Limits: records after the last bump are not anchored on the device; A2 can increment and sign. Counters are non-ORDERLY (A008 N4).

### 3.6 Loss and compromise
- TPM loss / Clear / RMA: keys and NV gone (ADR-002 R5); public verification of the old chain still works. A replacement device is provisioned
  (§6.1) with GENESIS committing to the old chain's last holder checkpoint.
- Suspected compromise: stop trusting the device; export; re-image (secure boot once available); then rotate. Records after the newest
  holder-received checkpoint before t0 are "unverifiable (compromise window)".
- Factory reset keeps audit files (DATA_MAP B8): factory_reset intent + outcome + exported CHECKPOINT before key destruction.

## 4. Record schema (v1, fixed little-endian, no free text)
### 4.1 Layout (tests/spec/layout_v0_3_3.py, log layout_v0_3_3.log; earlier scripts kept: body 144 B, EVENT 180 B, signed body 216 B, SIGNED 316 B, all fields naturally aligned)
| Off | Size | Field | Rule (violation = FAIL with reason code) |
|---|---|---|---|
| 0 | 4 | magic "CTAC" | [e_magic] |
| 4 | 1 | version | == 1 [e_version] |
| 5 | 1 | rec_type | 1 GENESIS, 2 EVENT, 3 CHECKPOINT, 4 EPOCH_START [e_rec_type] |
| 6 | 2 | event_code | §4.2 table for rec_type [e_event_code] |
| 8 | 4 | rec_len | 180 EVENT; 316 signed (v0.3.3, F60) [e_rec_len] |
| 12 | 2 | reason | per-code reason table, Appendix A (codes.hpp, frozen numbers) [e_reason] |
| 14 | 1 | actor_class | 0 none, 1 system service, 2 receiver service, 3 staff operator, 4 source/device (may be patient-linked) [e_actor] |
| 15 | 1 | dmethod | C4: digest method of THIS record: 1 KEYED (TPM2_HMAC, D_e), 2 ABSENT (fallback mode), 3 NOT_APPLICABLE (no keyed digest by the §4.2 rule; field follows §4.2), 4 KEYED_FAILED (§4.3); 5 RESERVED for the C8 option O1 (batched HMAC; FAIL in v1); 0 and 5-255 FAIL [e_dmethod] |
| 16 | 8 | seq | GENESIS 0, else previous + 1; 2^64-1 is FAIL [e_seq] |
| 24 | 4 | epoch | == current; +1 only on EPOCH_START IMMEDIATELY after a CHECKPOINT (A012 F76; otherwise e_epoch_handover); 2^32-1 FAIL [e_epoch] |
| 28 | 1 | len_bucket | Q9 power-of-two bucket (§4.4); 0 = unused; 1..65 valid (A009 F47: any u64 total) [e_field] |
| 29 | 1 | sflags | signed records: bit0 = TPMS_CLOCK_INFO.safe (A008 F43); bit1 = SUCCESSOR lineage (A009 F49): equals the GENESIS value in every signed record of the chain; bit2 = DIGEST_FAILED (A009 F52, A010 F60): set in the first signed record after any dmethod-4 record and in every later one, never clears; bits 3-7 = 0; EVENT: 0 [e_flag / e_reserved] |
| 30 | 1 | dmode | C4 chain/epoch digest configuration: signed records 1 KEYED or 2 ABSENT, set at GENESIS, changeable only at EPOCH_START, CHECKPOINT must repeat the current value; EVENT: 0 [e_dmode] |
| 31 | 1 | reserved1 | 0 [e_reserved] |
| 32 | 8 | ts_ms | WRITER-REPORTED wall clock UTC ms; regression = WARNING only (capped); codes 22/23: multiple of G_xfer (C3, §4.4) [e_ts_gran] |
| 40 | 8 | mono_ms | WRITER-REPORTED CLOCK_BOOTTIME ms; codes 22/23: multiple of G_xfer (C3) [e_ts_gran] |
| 48 | 8 | subj_first | §4.2 |
| 56 | 8 | subj_last | §4.2; >= subj_first when used, EXCEPT 22 reason 1 reseed (old -> new expectation may go down, F73) [e_field] |
| 64 | 4 | count | §4.2 [e_field] |
| 68 | 4 | actor_uid | staff uid in clear ONLY under §4.4 rules; else 0 [e_field] |
| 72 | 8 | bytes | EXACT byte totals only on recv_transfer_end with count >= 32 and on chain-internal events 64 (stub of a chain record); NON-LENGTH values on GENESIS (v_chain, F49) and 72 (groups count, F59); else 0 [e_field] |
| 80 | 32 | digest | §4.3; dmethod 1: non-zero required; dmethod 2/4: all-zero required; dmethod 3: §4.2 rule [e_dmethod] |
| 112 | 32 | prev_link | == h_{seq-1}; zero for GENESIS [e_link] |
| 144 | 8 | nv_export (signed) | §3.5 [e_nv_regress on device] |
| 152 | 8 | tpm_clock_ms (signed) | WRITER-REPORTED TPM2_ReadClock clock; corroboration only |
| 160 | 4 | tpm_reset_count (signed) | WRITER-REPORTED; decrease within an epoch = WARNING |
| 164 | 4 | tpm_restart_count (signed) | WRITER-REPORTED |
| 168 | 4 | recoveries_total (signed) | cumulative chain_torn_tail_recovered count (A008 F42); never decreases [e_counter] |
| 172 | 4 | gaps_total (signed) | cumulative lost-event count from chain_gap records (F42); += 1 at each level-4 entry and += max(1, count) - 1 at its 66 (A010 F61); += 1 per 22 reason 1 reseed (A012 F73); saturates at 2^32-1; never decreases [e_counter] |
| 176 | 4 | dfail_total (signed) | v0.3.3 (A010 F60): cumulative dmethod-4 (KEYED_FAILED) record count since GENESIS; saturates at 2^32-1; never decreases; > 0 iff sflags bit2 [e_counter / e_flag] |
| 180 | 4 | ext_reserved (signed) | 0 [e_reserved] |
| 184 | 32 | d_agg (signed) | CHECKPOINT: the §4.3 aggregate over EVERY EVENT digest in range, in every dmode (A011 F71) [e_dagg]; EPOCH_START: zero [e_field]; GENESIS: SHA-256("ct01.audit_chain.v1.genesis" ‖ predecessor commitment (32 B, zero if none/unknown) ‖ allowlist hash (32 B)) (A009 F58) |
| 144 / 216 | 32 | tag | HMAC-SHA256(K_e, DS_TAG ‖ h ‖ digest); CRYPTO_memcmp [e_tag] |
| — / 248 | 64 | sig (signed) | ECDSA P-256 r ‖ s, big-endian (SEC1); 1 <= r < n, 1 <= s <= n/2 [e_sig] |
| 176 / 312 | 4 | crc32 | IEEE CRC-32 over [0, rec_len-4) of the chain record; structural only [e_crc] |
History, size change v0.2 -> v0.3 (computed by layout_v0_3.py: sum of the field sizes, each naturally aligned): EVENT 180 B (unchanged; reserved1 u32 at 28
split into len_bucket u8 + sflags u8 + reserved1 u16); SIGNED 308 B (v0.2: 276 B; the signed extension grows from 32 to 64 B: the v0.2
ext_reserved u64 becomes recoveries_total u32 + gaps_total u32, and d_agg[32] is added for Q5). 144 + 64 + 32 + 64 + 4 = 308.
v0.3.3 size change (A010 F60, computed by layout_v0_3_3.py): SIGNED 308 -> 316 B: the signed extension grows 64 -> 72 B by dfail_total u32 +
ext_reserved u32 inserted before d_agg (keeps d_agg 8-aligned at 184); tag 208 -> 216, sig 240 -> 248, crc 304 -> 312. 144 + 72 + 32 + 64 + 4 = 316.
EVENT unchanged (180 B). This changes the M1 parser constants and the naive-verifier spec (A009 §7: 308 -> 316).
Torn-stub thresholds (§5.3): < 180 B (EVENT or unparseable header), < 316 B (signed).
Domain separation (ASCII, no terminator; distinct and prefix-free, checked): DS_LINK "ct01.audit_chain.v1.link", DS_TAG ".tag", DS_CKPT ".ckpt",
HKDF ".epoch_key", digests ".dgst.grp" ".dgst.act" ".dgst.torn" ".dgst.pred" ".dgst.agg" ".dgst.tpmrec", GENESIS ".genesis", allowlist ".allowlist", gap counter ".gapctr", Certify ".certify" (all prefixed "ct01.audit_chain.v1").
- Link (v0.3 change, Q5): h_n = SHA-256(DS_LINK ‖ chain_id ‖ body_n with the EVENT digest field replaced by 32 zero bytes). Signed-record digest
  fields (key ids, d_agg) are public and stay in the link. So holders and the SIEM verify links without ever seeing per-record digests.
- Tag: tag_n = HMAC-SHA256(K_e, DS_TAG ‖ h_n ‖ digest_n): binds the per-record digest under the device key.
- Signature: sig_n = ECDSA-P256(S_e, SHA-256(DS_CKPT ‖ h_n)) via TPM2_Sign (fixed 56-byte pre-image); EPOCH_START uses S_{e-1} (a claim).
- chain_id: 16 random bytes; GENESIS digest = chain_id ‖ first 16 B of S_0's key id.
- key_id (M1 ruling 1) := SHA-256(SEC1 uncompressed point, 65 B: 0x04 ‖ X ‖ Y), all 32 bytes, NO domain label (an identifier, not a MAC). Used in
  full in CHECKPOINT/EPOCH_START digests and --pubkeys; GENESIS carries its first 16 B. Ratifies the software_key_id
  (audit_chain/src/audit_record.cpp:182). Test vector (layout_v0_3_5.py): the P-256 generator G gives key_id
  698bea63dc44a344663ff1429aea10842df27b6b991ef25866b2c6c02cdcc5be (GENESIS prefix 698bea63dc44a344663ff1429aea1084).
- Allowlist hash (A009 F58) = SHA-256("ct01.audit_chain.v1.allowlist" ‖ u32le(n) ‖ sorted u32le uids); recorded in the inventory and bound into
  GENESIS d_agg (above); `ct01_audit_verify --allowlist FILE` recomputes it (e_allowlist); without the file the JSON says allowlist: "unchecked".

### 4.2 Event codes
| code | rec_type | event | subj_first..subj_last, count | actor | len_bucket / bytes | digest | class (§5.2) |
|---|---|---|---|---|---|---|---|
| 1 | GENESIS | chain created: reason 1 provisioning / 2 operator_init / 3 fail_successor / 4 missing_successor / 5 predecessor_unknown / 6 tpm_cleared; sflags bit1 = 0 only for reason 1, or 2 on an unprovisioned device (A009 F49). A011 F66: reasons 1, 2, 4, 5, 6 FORCE last good seq = 0, FAIL reason = 0 and v_chain = 0; only reason 3 carries them, and then a zero is a real zero (FAIL reason must be 1..40, Appendix A) [e_genesis] | subj_first = subj_last = predecessor last good seq (0 if none/unknown); count = predecessor FAIL reason code (e_* enum, 0 if none); nv_export = v_tpm at creation | operator uid (staff) or 0 | 0 / bytes = v_chain (newest nv_export in the predecessor's verified prefix; 0 if none/unknown) | chain_id ‖ S_0 id; d_agg = genesis hash (§4.1) | export now; always-bump CKP |
| 2 | CHECKPOINT | signed head | prev signed seq .. this seq; count = u64 difference that must fit u32 [e_ckpt_range] | 0 | 0 / 0 | signer key id; d_agg §4.3 | §2 cadence |
| 3 | EPOCH_START | key handover claim | 0 | 0 | 0 / 0 | key id of S_{e+1} | §3.4 |
| 16 | EVENT | recv_group_delivered | forward seq range; frames | 0 | bucket(group total) / 0 | grp (TPM2_HMAC; dmethod 1) or 0 (dmethod 2/4) | fail-closed, same sync as the group (§5.2) |
| 17 | EVENT | recv_void | seq..seq; 1 | 0 | 0 / 0 | 0 | fail-closed |
| 18 / 19 | EVENT | recv_export_intent / _outcome | seq range; records | staff uid | 0 / 0 | 0 | write-ahead |
| 20 / 21 | EVENT | recv_log_fault / recv_log_torn_tail | segment..segment; 0 | 0 | bucket(truncated bytes) / 0 | 0 | best-effort + sticky FAULT |
| 22 / 23 | EVENT | recv_transfer_start / recv_transfer_end (one forward session, HELLO to close). 22 reason 1 reseed (A012 F73): staff-authorized admin action only, actor_class 3 + allowlisted uid, FAULT, exit 6, holder alarm | session first..last seq; frames. 22 reason 1: subj_first = old expected seq, subj_last = new expected seq, count 0 | 0 (22 reason 1: staff uid) | end: bucket(total) / exact total only if count >= 32, else 0 | 0 | best-effort + sticky FAULT |
| 32 | EVENT | buffer_open | 0 | 0 | 0 / 0 | 0 | best-effort |
| 33 / 34 | EVENT | ack_purge_intent / _outcome | buffer seq range; records | 0 | 0 / 0 | 0 | write-ahead |
| 35 / 36 | EVENT | record_erase_intent / _outcome | seq..seq; 1 | staff uid | 0 / 0 | act or 0 | write-ahead |
| 37 / 38 | EVENT | factory_reset_intent / _outcome | 0 | staff uid | 0 / 0 | act or 0 | write-ahead |
| 39 | EVENT | buffer_fault | 0 | 0 | 0 / 0 | 0 | best-effort |
| 48-52 | EVENT | contingency_pass_through / nack_gap_replay / void_acked / kek_unavailable / mem_lock_failed | expected..got or 0; repeats | 0 | 0 / 0 | 0 | best-effort (51/52: §5.2) |
| 64 | EVENT | chain_torn_tail_recovered | newest exported checkpoint or bump checkpoint (§3.5) seq .. first missing seq; subj_first < subj_last REQUIRED | 0 | 0 / stub bytes (chain metadata, exact) | SHA-256(".dgst.torn" ‖ quarantined bytes) | export now |
| 65 | EVENT | chain_predecessor | old last good seq..same; 0 | 0 | 0 / 0 | SHA-256(".dgst.pred" ‖ old chain_id ‖ old last good link ‖ u64le(seq)) or 0 if unknown | export now |
| 66 | EVENT | chain_gap (signed gap marker once covered by the next CHECKPOINT); reasons fail_successor, unrecordable, audit_space (level 4), count_unknown | first..last seq of the gap (level 4: forward seq range of the episode; it must start at the forward-seq expectation, A011 F70 lower bound, e_gap_range); count = lost events / groups; >= 1 always (count_unknown when unknown, A009 F49) | 0 | 0 / 0 | 0 | before the next append (control slice, §5.6) |
| 67 | EVENT | holder_ack | acked checkpoint seq..same; holder id 1 or 2 | 0 | 0 / 0 | 0 | best-effort |
| 68 | EVENT | recv_coverage (M1 ruling 5: Appendix A name; reasons coverage_mismatch / group_rolled_back / recvlog_sync_failed / duplicate_content_mismatch) | recvlog committed seq .. chain coverage | 0 | 0 / 0 | 0 | best-effort + FAULT |
| 69 | EVENT | fault_ack (admin acknowledges the latched FAULT; Q6) | seq of the FAULT-raising record..same (reason gap: MUST name a 66, A010 F64 [e_ack_ref]); 0 | staff uid | 0 / 0 | 0 | fail-closed (control slice; the ack takes effect only after it returns) |
| 70 | EVENT | config_mismatch (audit_chain=off on a provisioned device, §6.1; reason nv_tampered, F63) | 0 | 0 | 0 / 0 | 0 | best-effort + FAULT |
| 71 | EVENT | tpm_recovered (C7: TPM2_HMAC works again) | first..last dmethod-4 seq; count = dmethod-4 records, saturating at 2^32-1; reason saturated IFF count == 2^32-1, both directions, mismatch = e_reason (M1 ruling 4; the u64 range stays exact) | 0 | 0 / 0 | SHA-256(".dgst.tpmrec" ‖ h of the last dmethod-1 record before the failure), dmethod 3: chains from the last good link | export now |
| 72 | EVENT | recv_groups_compacted (C5 ladder step d); reason normal / rebuilt (from the aggregate slot after a crash, F59) | forward seq range of <= 60 s of groups; count = frames | 0 | bucket(total) / bytes = groups count | grp over all frames of the range (dmethod per dmode) | fail-closed, same barrier as the groups |
| 73 | EVENT | commissioning_verified (C6) | 0; count = NV_commissioned handle | staff uid | 0 / 0 | 0 | export now |
| 74 | EVENT | lockdown (M1 ruling 5: Appendix A name; reasons failed / restored; C6 rule 2) | 0; count = retries | 0 | 0 / 0 | 0 | best-effort + FAULT; verifier: JSON warning only (A010 F64) |
| 75 | EVENT | audit_space_level (reason = ladder level 1-4, plus reserve_tampered, C5/F62) | 0 | 0 | 0 / 0 | 0 | control slice; FAULT from level 2; step rule §6.2 [e_level] |
Appendix A is NORMATIVE for code names and reason values; prose names here follow it (M1 ruling 5).
Numeric reason values for every code, the e_* FAIL reasons and the per-code exit effect: Appendix A (frozen; never renumbered).
Not representable: payload, patient_ref, paths, host names, free text, unkeyed checksums or hashes of frame bytes, exact per-frame or per-group lengths.

Reseed (A012 F73; by M4, text now): ct01_recv re-ACKs every frame below its single global expected seq as a duplicate without delivering
it (ct01/src/recv/main.cpp:16, :261; one global expected seq at :1248-1251), so changing the expectation (`--expect-start`, failover to another
receiver) can silently drop frames. Threat: A1 edits a unit/config file and restarts. Rule: in the M4 copy the expectation changes only
through `ct01_audit_admin reseed --expect N` run by a staff admin (actor_class 3, allowlisted uid, §4.4); it appends 22 reason 1 (fail-closed:
the new expectation applies only after the record is durable) with subj_first = old, subj_last = new expected seq; it latches FAULT `reseed`,
alarms both holders, and the next CHECKPOINT adds 1 to gaps_total (so the exit-6 qualifier `reseed` survives pruning). A `--expect-start` on
a provisioned host without that record is ignored + config_mismatch (70).
### 4.3 Keyed digests (Decision 2026-11-11, Q5: CLOSED, accepted under conditions)
- grp = TPM2_HMAC(D_e, "ct01.audit_chain.v1.dgst.grp" ‖ inner), inner = SHA-256(u32le(n) ‖ for each frame: u64le(seq) ‖ u32le(len) ‖
  SHA-256(frame bytes)). inner is computed in locked scratch and wiped; never stored or exported. One TPM command per recv group (§2).
- act = TPM2_HMAC(D_e, "ct01.audit_chain.v1.dgst.act" ‖ u8 kind ‖ u32le(len) ‖ id bytes); kind 2 = operator token (<= 64 B), kind 3 =
  source/device id (pseudonym for actor_class 4, §4.4). (kind 1 = numeric uid is no longer digested: Q10 puts staff uids in clear.)
- d_agg (CHECKPOINT; the ONLY d_agg rule, A011 F71) = SHA-256("ct01.audit_chain.v1.dgst.agg" ‖ the 32 B digest field of EVERY EVENT in (prev
  signed seq, this seq], in seq order, zeros included), in every dmode; it therefore also binds the public 64/65/71 digests. GENESIS d_agg is
  NOT an aggregate: it is the genesis hash of §4.1 (predecessor commitment ‖ allowlist hash). EPOCH_START d_agg is zero.
  It is the only digest-derived value a holder or the SIEM receives; it is a hash of TPM-keyed HMAC outputs, so nobody without D_e can test a guess.
Condition check against the decision:
| Condition | v0.3 |
|---|---|
| separate and domain-separated from the MAC chain key | D_e is an independent TPM object, not derived from R^t_e; own labels | MET |
| TPM-held | D_e is fixedTPM, used only through TPM2_HMAC; it never enters host RAM (v0.2 derived it into RAM: changed) | MET (verified at M2) |
| never given to the holder or SIEM | no export path; no escrow (Q2) | MET |
| rotated per epoch | new D_e per epoch, PolicyNV(NV_epoch == e) | MET |
| digests reach the holder only inside checkpoints | v0.2 exported per-record digests in JSONL and in "raw": CHANGED. JSONL omits digest and raw (§6.4); the link excludes the EVENT digest (§4.1); holders get d_agg in checkpoints only | MET |
Fallback (Decision 2026-11-11, C4: CLOSED, ACCEPTABLE with three conditions):
1. Explicit, no size change: per-record `dmethod` (offset 15, the former reserved0) and per-chain/epoch `dmode` (offset 30, the former high
   half of reserved1) say which method applies. dmethod 0 is invalid, so a zeroed record never reads as anything; digest = 0 is legal only
   with dmethod 2 (ABSENT), 3 (NOT_APPLICABLE) or 4 (KEYED_FAILED), and dmethod 1 requires a non-zero digest. Both bytes are inside the link,
   tag and (signed records) signature, so they cannot be flipped without FAIL.
2. Build/config, never a runtime switch: `audit_chain_digest = keyed | absent` (ct01.conf; Release default keyed) is read ONLY when a GENESIS
   or EPOCH_START is written and copied into its dmode. The writer holds the mode immutable for the epoch; editing the config takes effect
   only at the next rotation or successor chain, which are signed and alarmed (§6.3). Consistency (verifier, e_dmode / e_dmethod = FAIL):
   EVENT dmethod must agree with the dmode of its epoch: dmode 1 -> digest-bearing records (16 always; 35-38 when an operator token exists)
   carry 1 or 4, never 2; dmode 2 -> those records carry 2, never 1 or 4; every other record carries 3. A CHECKPOINT whose dmode differs from
   the epoch's GENESIS/EPOCH_START is FAIL. d_agg follows the single §4.3 rule in every dmode (the v0.3.1-v0.3.3 "dmode 2: zero" and "dmethod-1
   digests only" sentences are withdrawn, A011 F71).
3. Never a software digest key: digests come from TPM2_HMAC with D_e or do not exist. The Release writer has no code path that builds a
   software D_e (the DEV-ONLY software HMAC key in §3.1 is compiled only into test/dev targets; a Release CI check asserts the symbol is
   absent); a dev-built chain is never accepted by a holder.
Runtime TPM2_HMAC failure under dmode 1 (C7, CLOSED: ruled, CT-01 2026-11-11): the record is written with dmethod 4
(KEYED_FAILED, digest zero), FAULT `digest_failed` latches (admin fault_ack, §5.5), the group is still ACKed (G7: delivery never stops on an
audit-path failure) and the verifier counts it. This is not a mode switch: dmode stays 1, the failure is per record, visible and signed into
the next checkpoint. When TPM2_HMAC succeeds again the writer appends record 71 tpm_recovered (C7 addition), which chains from the last good link: its digest
commits to h of the last dmethod-1 record before the failure and its range/count cover exactly the dmethod-4 run (verifier recomputes both;
mismatch = e_tpmrec FAIL). The FAULT still needs the admin fault_ack.
C7 ruled conditions (Decision 2026-11-11): (i) no software-key fallback (no D_e outside the TPM in Release, as above);
(ii) TPM2_HMAC is retried with backoff (same PROPOSED schedule as §3.1: 1 s doubling to 15 min) while each failing group still gets dmethod 4;
(iii) the affected count is recorded (record 71 count, plus the signed running total dfail_total at offset 176 of every signed record and the
sticky sflags bit2, both v0.3.3 layout fields, A010 F60); (iv) the recovery record 71 chains from the last good link.
Bounded retries (A009 F52): per group, at most 2 immediate retries on transient TPM_RC_RETRY / TPM_RC_YIELDED / TPM_RC_TESTING within the group
budget, then dmethod 4; any other RC -> dmethod 4 at once; the 1 s .. 15 min backoff (ii) governs re-probing after the failure, not per group.
D_e and S_e are noDA (§3.1). Exit: dmethod 4 -> bit2 -> exit 6 (§6.2), permanent (survives pruning: signed bit2 + dfail_total).
JSONL/SIEM export without digest, tag and raw: CONFIRMED (Decision 2026-11-11, C4). dmethod and dmode ARE exported
(needed to recompute links); they reveal only whether a keyed digest exists, which actor_class already implies.

### 4.4 Lengths and actors (Decisions 2026-11-11; Q9 and Q10 CLOSED, settled for the M0 freeze)
Q9, bucketed lengths: len_bucket = 0 if unused, else 1 + ceil(log2(len)), i.e. bucket k covers (2^(k-2), 2^(k-1)] bytes (k=1: 1 B; k=7: 33-64 B).
Range (A009 F47): 1..65, covering every u64 (bucket(2^64-1) = 65). Chosen over saturating at 33 because a session total passes 4 GiB in
65-183 s at the measured 66.17/23.43 MB/s (CT01D.md:245-246, a009 q9_leakage.log), and a 72 aggregate over 60 s can approach it too;
saturation would need a special rule and would make a legitimate long transfer look like a capped one. No per-frame field can reach
> 33 (frames <= 64 KiB), so the extra buckets add no per-frame information.
Choice: POWER-OF-TWO, not 64-byte buckets. Frames range from ~48-50 B for synthetic vitals (a008 crc_oracle_v02.log length classes 48/49/50) up
to max-block frames of tens of KiB. 64-byte buckets would still give ~1,000 distinguishable classes at the large end and split small frames at
every 64 B; power-of-two gives 18 classes over 1 B .. 128 KiB (arithmetic, layout_v0_3.py) and puts all three observed vitals lengths in one
bucket (k=7), i.e. 0 bits in the A007/A008 guess space. Exact totals appear only as aggregates in `bytes` on recv_transfer_end, and only when
count >= 32 frames. Decision 2026-11-11 (C3: CLOSED, CONFIRMED): transfers under 32 frames keep only bucketed
totals; the threshold is counted in FRAMES (`count` of code 23 = frames in the session's seq range), not bytes or groups.
Timestamp rule (C3): transfer start/end timestamps must be no finer than the per-frame record timestamps, so totals cannot be recovered by
differencing. Writer enforcement: one quantizer in ChainWriter (no caller passes a raw time for 22/23); per-group records (16) keep 1 ms;
codes 22/23 write ts_ms and mono_ms as floor(t / G_xfer) * G_xfer with G_xfer = 1000 ms (spec constant in v1, >= the 1 ms of code 16),
and the end time is max(quantized now, quantized ts of the last code-16 record in the range), so the end never adds sub-second timing
the group records do not already carry. Verifier: ts_ms % 1000 != 0 or mono_ms % 1000 != 0 on 22/23 is FAIL e_ts_gran.
Design addition (stricter, same aim; this may be relaxed): exact totals are per transfer, never cumulative, and an exact total is written
only if the session's seq range does not overlap the range of any earlier exact-total code 23 in the chain (a reconnect replays unACKed
seqs, so overlapping totals would allow T_a - T_b differencing). Otherwise only bucket(total). The writer derives the highest exact-covered seq
from the chain at open; the verifier checks it (e_xfer_overlap). A009 F54: on a successor chain, or when pruning removed the newest exact-total
23, exact_hi starts at the recvlog's max forward seq, so no exact total is written until a session starts above it (conservative).
Residual (A009 F54, a009 q9_leakage.log; noted): at >= 32 frames, if 31 of the 32 lengths are known or predictable
(fixed-size heartbeats, VOIDs), total minus the known lengths = the remaining frame's EXACT length (leave-one-out). Accepted by the >= 32
rule as ruled; it may be tightened later (e.g. bucketed totals always). Group totals
(event 16) are bucketed. The keyed grp digest still includes exact lengths (keyed, TPM-held, not exported).
Test (§8.7): no per-frame or per-group field carries an exact length (records for lengths L != L' in the same bucket are byte-identical in all
unkeyed fields; `bytes` == 0 except the two allowed cases).
Q10, actor ids: workforce uid in clear, with conditions. (a) The writer sets actor_uid != 0 ONLY when actor_class is 1, 2 or 3 AND the uid comes
from the local process credentials (getuid()/SO_PEERCRED of a local admin command) AND it is in the provisioned staff/service uid allowlist
(numbers only, in the inventory, installed read-only with the release). Patients and wearables never have local Unix accounts, so they can
never pass this test; any actor that is a source/device (actor_class 4: paired or ACKing wearable, ingest client) gets actor_uid = 0 and, if an
id is needed, a keyed pseudonym (act kind 3) or a role token in `reason`. A uid not in the allowlist -> actor_uid = 0, reason
actor_unregistered, FAULT-class warning. Registry rule (A009 F58): uids are never derived from patient ids (an admin creating a uid equal
to an MRN is a registry violation); the allowlist hash is in GENESIS (§4.1). The verifier rejects actor_uid != 0 with actor_class 0 or 4 [e_field]. A patient-linked id in clear is
unrepresentable. (b) The uid-to-person registry is access-controlled, kept outside the log, and REQUIRED BEFORE PILOT (owner: compliance, with
customer IT; §12 pre-pilot list). A shared service uid attributes actions to the service, not a person (A008 §6).

## 5. Crash safety and durability
5.1 Files, lock, space: `<state>/audit_chain/chain_<chain_id hex>_<NNNNNNNN>.ac` (0600; closed 0400), O_WRONLY|O_APPEND|O_CLOEXEC|O_NOFOLLOW;
one write() per record; roll at 64 MiB. flock(LOCK_EX|LOCK_NB) on `.lock` for the writer's life, taken before self-check and recovery.
Directory fsync after every create and rename; it must COMPLETE before the first ACK of any group whose record is in the new segment
(A009 F55). Mode changes (closed segments 0400, quarantine files) are fchmod(fd) + fsync(fd): inode metadata, not covered by the directory
fsync or by fdatasync (F55). Write errors (A009 F51): a short write or ENOSPC from write() = nothing new assumed durable: ftruncate to the
boundary and continue on the §5.6 ladder. EIO from write(), or ANY error from fdatasync/fsync on the chain fd = the chain has FAILED: the
writer NEVER retries fdatasync on that fd (after a writeback error Linux may drop the dirty pages and report success next time), closes it,
and starts the §5.4 successor in a fresh segment. If the successor cannot be created or synced: §5.6 level-4 handling (count-only, durable
counter file). The writer is BROKEN only if neither works.
Space (A008 F41.4; Ruling 2026-11-11, C1; watermark behaviour REPLACED by the joint C5 ruling): ONE dedicated log
filesystem (its own partition on the Pi) holding only the recvlog and the audit chain on the receiving host (only the ct01d chain on the
device), instead of a quota. Audit segments are preallocated with fallocate (FALLOC_FL_KEEP_SIZE) at roll. The reserved-space watermark (value
set at M4 from the measured event rate, UNMEASURED) no longer stops ACKs: crossing it starts the §5.6 ladder. ACKs never stop for audit
storage; a group is still ACKed only after the record is durable at the current ladder level (or counted, level 4). Arithmetic for sizing (not
a measurement): one EVENT record per recv group, 180 B x <= 50 groups/s = 9,000 B/s = 32.4 MB/h = 777.6 MB per 24 h at the full group rate.
5.2 Durability classes (A007 F30; Ruling 2026-11-11, Q11: approved IN PRINCIPLE, NOT signed off)
| Class | Events | Rule |
|---|---|---|
| fail-closed (ladder levels 1-3; level 4 counted, §5.6), same durability barrier as the recv group | 16, 17 | Ruling 2026-11-11 (C1, CLOSED): Q11 means ONE durability barrier per group commit, not one syscall. Preferred: write the chain record and the recvlog group (incl. COMMIT), then fdatasync the recvlog fd and the audit-chain fd IN PARALLEL (two threads or io_uring); ACK the group only after BOTH succeed; directory fsync on segment create, as today. Fallback only: one syncfs(2), which needs kernel >= 5.8 (error reporting) and a filesystem holding only the two logs; CHECKED AT OPEN (A009 F55): uname release >= 5.8 AND st_dev(recvlog dir) == st_dev(chain dir) AND the mount is the dedicated log mount (mountinfo) with no top-level entries other than recvlog/, audit_chain/ and lost+found; otherwise the parallel path is used. recvlog-fd failure = no ACK for that group (the data is not durable): RecvLog rolls back to the last COMMIT and rotates (recv_log.cpp:645-658),
the receiver's expected seq rolls back, ct01d keeps the frames and replays them under the same seq after reconnect (CT01D.md:197), and the
writer appends 68 recv_group_rolled_back (reason recvlog_sync_failed) for the group's chain record if that record is durable; the replay gets a
fresh 16. Audit-fd ENOSPC = §5.6 ladder (ACK continues); audit-fd EIO or any audit-fd fdatasync error = chain FAILED (no fdatasync retry, F51)
-> §5.4 successor in a fresh segment + FAULT (Q6); the in-flight group's 16 is re-appended in the successor and the group is ACKed only after
that barrier succeeds; delivery continues. The v0.3 syncfs-first proposal is replaced. The Q11 gates (§12 M4) still apply. |
| write-ahead | 18/19, 33/34, 35/36, 37/38 | INTENT returns OK (own fsync, ct01d side, not the recv group path) before the destructive or plaintext-exiting action; intent failure = action refused; outcome best-effort + FAULT. The ct01d ack_purge intent adds one fsync per purge batch: included in the M4 measurements. |
| best-effort + sticky FAULT | 20-23, 32, 39, 48-50, 67, 68, 70, outcomes | failure -> latched FAULT (§5.5) and a chain_gap before the next successful append |
| unrecordable at the time | 51, 52, and any period with the chain unavailable | existing text audit/journald; on the next open a chain_gap (from the fixed-size metadata-only counter file) records them. Counter file (v0.3.3, A010 F61): two 128 B slots written alternately with pwrite (slot = magic, chain_id, epoch, episode id, write counter, first/last forward seq, groups, frames, reason, HMAC-SHA256(K_e, DS ".gapctr" ‖ slot)); the newest valid slot wins; fdatasync'd inside the group barrier whenever it carries ACKed groups (level 4) |
v0.2's "one extra fsync per recv group" and v0.3's single-syncfs proposal are both withdrawn; the barrier is the parallel pair above.
Crash reconciliation at ct01_recv open (both directions, at most one in-flight group; v0.3.1 lost this lead-in by an edit slip, restored): recvlog committed but no chain record -> recv_group_delivered reason=recovered_unacked; chain record present but
recvlog group not committed -> recv_group_rolled_back (68); anything larger -> 68 + FAULT.
5.3 Torn-tail rule (newest file only): region from the first structurally failing record to EOF is torn iff its length < rec_len of the record it
starts (header parse) or < 180 B (unparseable). Against A1 = arbitrary truncation. Anything else = FAIL.
5.4 Recovery and FAIL handling (A008 F41; Decision 2026-11-11, Q6: CLOSED, AGREED)
Recovery (torn tail, under the lock; only after the §3.5 open sequence steps 1-2 passed, A009 F48): (1) refuse if the boundary is at/below the
bump checkpoint (§3.5) or a holder-ACKed one -> FAIL; (2) quarantine region to torn_<chain_id>_<seq>.bin, fsync, fchmod 0400 + fsync, dir fsync; (3) ftruncate + fsync; (4) append event 64 + CHECKPOINT
(recoveries_total + 1; ALWAYS bumps NV_export: append, fsync, TPM2_NV_Increment, A009 F57); export to both holders immediately; FAULT latched (§5.5).
FAIL (any verified failure, e_nv_regress, e_nv_epoch): never modify the file; chmod 0400 + dir fsync; then automatically, in this order:
(a) GENESIS of a successor chain, reason fail_successor, sflags bit1 = 1, predecessor commitment SHA-256(".dgst.pred" ‖ old chain_id ‖ last good
    link ‖ u64le(last good seq)) bound into d_agg (§4.1), FAIL reason code, last good seq, v_chain and v_tpm in the §4.2 GENESIS fields (A009 F49);
    keys per §3.1 (F56) if the old ones are unusable (signed);
(b) chain_predecessor (65) with the same commitment, and chain_gap (66) = the signed gap marker: old-chain seq range from last good + 1 to the
    end as found, count = records not verified;
(c) CHECKPOINT (signs (b); always bumps NV_export, F57); export to both holders; FAULT latched. DELIVERY CONTINUES (fail-closed appends now go to the successor).
Missing or empty chain on a provisioned device (NV_epoch defined) = suspected tampering, not first boot: same FAULT and the same successor
sequence with reason missing_successor; the predecessor commitment references the last checkpoint FETCHED FROM A HOLDER. Before M4 (no holder)
or with no holder reachable: commitment = 0, reason predecessor_unknown, plus the TPM NV_epoch/NV_export values in the GENESIS extension; when a
holder becomes reachable, the writer appends chain_predecessor with the holder's checkpoint. Holder fetch (A009 F49, M4): at successor creation
and at every open with a holder reachable, the device FETCHES both holders' last checkpoint for the predecessor chain_id, verifies its signature
against the pinned keys, and records it in 65; if the holder's seq > last good seq, the 66 count is at least the difference. Never a silent re-genesis: every successor GENESIS is
signed, exported immediately, latches FAULT and is alarmed by holders.
5.5 FAULT latch (Q6): FAULT raised by any chain event stays latched across restarts (recorded in the chain itself, recomputed at open) until a
staff admin runs `ct01_audit_admin ack-fault`, which appends fault_ack (69) with the actor uid; the latch clears only after that append returns.

5.6 Audit storage ladder (C5, CLOSED: FORMAL JOINT RULING, CT-01 2026-11-11; REPLACES C1 backpressure)
The v0.3.1 analysis found a conflict in rationale (C1 backpressure let an A1 who fills the log filesystem stop all receiver ACKs, the lever Q6
removed). The ruling: the ladder below is THE behaviour (no config or build switch back to backpressure); ACKs never stop for audit storage.
Level 0, step (e), always on: the log filesystem is writable only by the receiver service user; every level change is alarmed off-box at once
  (both holders + SIEM) and written as record 75. C5 hardening (A009 §5, by M4 GO): mount point 0700 owned by the receiver user; ext4 reserved
  blocks with resuid = the receiver user (`tune2fs -r N -u <uid>`), sized for N hours of audit (arithmetic: 32.4 MB/h at full rate); a project
  quota on the recvlog directory so data growth cannot consume the audit reserve; per-device ingest rate limits in ct01_recv (values set at M4,
  UNMEASURED). Root can always fill it (A2, stated).
Control slice (A010 F61): a separate 1 MiB file, preallocated and protected like the reserve, used ONLY for records 64-75 and CHECKPOINTs, so the
  ladder's own records (75, 66, 69, 72's rebuild, and the entry/exit CHECKPOINTs) can always be written.
Reserve protection (A010 F62): the reserve and control-slice files are owned by root, mode 0400, opened O_RDWR by a root helper (systemd
  OpenFile= or the provisioning helper) and passed to the writer as fds; the writer sets PR_SET_DUMPABLE 0 so its /proc/<pid>/fd is root-only.
  Detection as well: fstat st_size and st_blocks at every level change, every CHECKPOINT and every reserve write; any shrink or hole = tamper:
  FAULT `reserve_tampered`, record 75 reason reserve_tampered from the control slice, holder alarm.
Level 1, normal: preallocated segments, one record 16 per group, C1 barrier (parallel fdatasync, ACK after both).
Level 2, step (b), emergency audit reserve: entered when a segment cannot be preallocated or free space < watermark. The reserve is a file
  fallocated at provisioning and held open by the writer from boot (an A1 filling the filesystem cannot take its extents); PROPOSED size
  24 h at the full group rate = 777.6 MB (arithmetic). Full per-group records continue; FAULT `audit_space` latches.
Level 3, step (d), compact records: when the reserve is > 50% used (PROPOSED), one record 72 per <= 60 s of groups (~60 x fewer bytes at the
  full rate, arithmetic) with a keyed grp digest over the range (one TPM2_HMAC per record). A010 F59: a 60 s record cannot share each group's
  barrier (2 s ACK deadline, protocol.hpp:28). So each group is ACKed after the C1 barrier of the recvlog fd and the AGGREGATE SLOT (the §5.2
  counter-file mechanism, K_e-tagged: open window's forward seq range, groups, frames); the 72 is appended (with its own barrier) when the window
  closes. Crash: the 72 is rebuilt from the slot, never from the recvlog alone, with reason rebuilt and dmethod 4 (the window's digest inputs
  were in RAM only: storing a running hash of frame hashes would be an unkeyed ePHI function, F27 class), so bit2 -> exit 6. Records 17, 22, 23,
  67, 68 (and all other codes) are still written one by one at level 3. Arithmetic (a010 sizing.log): level 3 starts after ~12 h at the full
  per-group rate, then the remaining reserve lasts ~1,500 days.
Level 4, bounded step (c), count-only GAP: reserve exhausted: groups are still ACKed; GAP FAULT latches. Ordering (A011 F67): the entry 75 and
  the entry CHECKPOINT (TPM2_Sign, fdatasync, then the TPM2_NV_Increment returned) are durable BEFORE the first count-only ACK; until they are,
  each group stays fail-closed (no ACK; ct01d replays), and the writer retries the entry (persistent entry failure: C13). v0.3.3 (A010 F61): on ENTRY the
  writer appends 75 (level 4) and a CHECKPOINT from the control slice with gaps_total += 1 (always bumps NV_export), so the episode is signed and
  exit 6 holds from its first second even if space never returns; the count (forward seq range, groups, frames) lives in the K_e-tagged
  counter file, fdatasync'd in every group's barrier (no RAM-only count), and in the off-box alarm stream. Exit: the 66 adds max(1, count) - 1,
  so every episode adds >= 1 to gaps_total. Holders FAIL (e_gap_count) if a later 66 count is below their last alarmed count; the verifier
  checks the 66 range against the forward-seq expectation (A011 F70: a lower bound for 66 only; §6.2 contiguity rule; e_gap_range). By arithmetic level 4 is
  practically unreachable through audit volume (a010 sizing.log), so entering it means tampering, misconfiguration or a missing reserve. Bounded because: (i) the recvlog keeps the delivered data, so after a
  crash the gap is rebuilt from the counter file (v0.3.3), with recvlog vs chain coverage only as a cross-check (the recvlog is not chained and can be cut at a COMMIT boundary, A010 F61); (ii) as soon as space returns the writer
  appends record 66 chain_gap (reason audit_space, count = groups without a per-group record), covered by the next CHECKPOINT, so gaps_total
  rises and every later verification exits 6 (ok_recovered, permanent); (iii) the HIPAA bounds below.
HIPAA bounds on GAP (same ruling):
- The GAP FAULT stays latched until an admin acks it; the ack is itself an audit record: REUSE record 69 fault_ack with reason `gap` and
  subj_first = seq of the record 66 it acknowledges (fail-closed: the ack takes effect only after it is durable, i.e. after space returns).
- A gap open > 24 h escalates to incident review (holder alarm `gap_24h`), matching the device 24 h retention FAULT (ct01_buffer.h:9, :61).
  A010 F65 recommends incident review at level-4 ENTRY, keeping gap_24h as a second escalation: OPEN before pilot (C12);
  not decided here (holders already alarm on entry).
- Every gap (each record 66 and each level-4 episode) goes into the customer's risk analysis and incident log (runbook item; holders export
  the record 66/69 pairs for it). This is a process requirement, not a compliance claim (§10).
Scope: the ladder covers AUDIT storage only. If the shared partition is so full that the recvlog itself cannot commit, the receiver cannot
ACK durable data at all: existing recvlog behaviour (ENOSPC, writer BROKEN), and the device then buffers: 2.0 GiB, WARNING >= 60% / 30 min,
FAULT >= 85% / 4 h, at 100% CT01_E_FULL and 'F' to sources ("never silent drop"), 24 h retention FAULT (ct01_buffer.h:6-9, :56, :61;
CT01D.md:97; STATUS_UI_CONTRACT.md:74). Sensor-side loss then depends on per-integration source retention, an open pre-pilot condition
(2026-10-19 11:39 ET). The fallocated audit areas make sure audit is never the cause of that case.
What the clinician sees: on the device kiosk nothing changes at levels 1-4 (ACKs continue, state OK, data reaches the clinical system).
Audit-storage state is visible only on the receiver status, the holders and the SIEM. An 'audit full' wire reason code to show it on the
device is a pre-pilot protocol change, routed through the transport ADR; a nice-to-have, not a pilot blocker; nothing in the demo.
Tests: §8.9 (ladder).
## 6. Verifier, outputs and the holder contract
### 6.1 Chain creation and the off switch (A008 F40, F41)
- Chains are created at provisioning (reason provisioning) or by `ct01_audit_admin init` (operator_init), and automatically only as the
  §5.4 successor (fail_successor / missing_successor, always with predecessor commitment + FAULT). init REFUSES when NV_epoch is defined or an
  earlier chain exists unless it writes chain_predecessor (from the old chain's last good record, or the holder's last checkpoint, or
  predecessor_unknown + FAULT).
- The requirement is TPM-resident: if NV_epoch is defined, the chain is REQUIRED regardless of config. `audit_chain=off` or a missing
  `--audit-chain-dir` on a provisioned device is ignored: the chain runs (successor if missing) and config_mismatch (70) latches FAULT.
  Config cannot override this (same spirit as the CT01D.md:178 fail-closed KEK rule). Only an unprovisioned DEV/M1 build honours
  `audit_chain=off`; a RELEASE build never does (A009 F50): no NV_epoch in Release = FAULT `tpm_cleared` + successor (§3.1). A missing
  `--audit-chain-dir` falls back to the compiled-in default `/var/lib/ct01/log/audit_chain` on the dedicated log mount (A009 F58), plus
  config_mismatch (70).
- Nothing ever "refuses to start" because of the chain: the daemon starts, reports FAULT in /status, and delivery continues (G7).
### 6.2 Offline verifier `ct01_audit_verify` (read-only, never creates keys)
Inputs: ordered chain files (regular, O_NOFOLLOW, <= 64 MiB + 316 B, order by name AND seq); `--pubkeys FILE` (per-epoch S_e public, key id,
pinned [first, last] seq; inventory/Certify-sourced only); `--anchor seq:link:chain_id`; `--checkpoints FILE` (Q1 ruling: verify OFFLINE from
exported checkpoints alone: signatures, pinned ranges, prefix consistency, recoveries/gaps totals, and fork comparison of two holders' exports
with `--checkpoints A --checkpoints B`); `--epoch-key e:FILE` TEST-ONLY / on-device (Q2: no escrow).
Exit codes are a STABLE API (A008 F46):
| exit | result | meaning |
|---|---|---|
| 0 | ok | every record covered by a verified signature or tag, anchor given and matched, recoveries_total == 0, gaps_total == 0 |
| 1 | io/usage | (note: an ASan abort also exits 1) |
| 2 | FAIL | reason + first_bad_seq; includes a fork (Q1: any (epoch, seq, head) mismatch across holders/device is a visible FAIL) |
| 3 | ok_torn_tail | unrecovered torn stub |
| 4 | ok_unanchored | no anchor: `anchor: none` |
| 5 | ok_tail_unverified | public mode, records after the last signature |
| 6 | ok_recovered | in the newest signed record: recoveries_total > 0, gaps_total > 0 (incl. reseeds, F73), sflags bit1 (successor lineage, A009 F49) or sflags bit2 / dfail_total > 0 (digest failed, A009 F52 / A010 F60). Permanent: all are signed and survive pruning (A008 S3c). JSON qualifiers: recovered, gap, successor, digest_failed, reseed; plus fwd_seq_jump from the records present (F74) |
| 7-9 | reserved | future qualifiers; scripts must treat them as qualified-accept only after a documented API update |
A qualified accept is 3 <= rc <= 6 (NOT rc <= 6, which would accept 1 and 2). Several qualifiers can hold; exit = first applicable of
6, 5, 4, 3; JSON `qualifiers[]` lists all. The SAME precedence function is used by the device self-check and the CLI (one shared module).
Before M4 every real verification returns 4 (no holders): runbooks must NOT whitelist 4 generally; 4 is accepted only for named pre-M4 test
procedures. Exit 0 with an anchor does NOT mean "nothing deleted above the anchor" (a008 S5): JSON reports records_after_anchor.
JSON: result, qualifiers[], anchor ("none" | {seq, matched}), records_after_anchor, reason, first_bad_seq, last_verified_seq, last_signed_seq,
tail_unverified_from, torn_bytes, recoveries_total, gaps_total (from the newest signed record), clock fields labelled "writer_reported",
epochs[] (cap 64 + total), warnings[] (cap 100 + total). Enums from fixed tables; unknown values as numbers; NO paths (stderr only); u64 as
decimal strings. Reason codes: §4.1 codes + e_short, e_no_genesis, e_behind_anchor, e_anchor_mismatch, e_ckpt_range, e_epoch_handover,
e_unexpected_chain_id, e_file_order, e_counter, e_fork, e_nv_epoch, e_nv_regress (device only), e_dmethod, e_dmode, e_ts_gran, e_xfer_overlap, e_tpmrec, e_flag, e_genesis, e_allowlist, e_gap_range, e_gap_count (holder), e_ack_ref, e_level, e_dagg. Numbers: Appendix A.
Digest reporting (C4; no new exit code; dmode 2 ABSENT is not a qualifier, while KEYED_FAILED is (bit2 -> 6, A009 F52)): JSON `digest` = {mode: "keyed" | "absent" | "mixed" (epochs differ),
keyed_records, absent_records, failed_records, verified_against_data: false} plus per-epoch dmode in epochs[]; stderr prints "DIGEST ABSENT"
or "DIGEST FAILED n" when non-zero. Exit 0 attests chain integrity (links, tags, signatures, anchor), NEVER content binding: no verifier
re-computes a digest (D_e is TPM-only, inputs are wiped), so even dmethod 1 is reported as "present and tagged", not "verified".
Inconsistent method/mode = exit 2.
Check order (M1 ruling 0, normative: AUTHENTICATE BEFORE SEMANTICS; replaces the v0.3.4 "fields before tag" order):
1. Framing: rec_len and the bytes needed to locate the record and its tag (magic, version, rec_type, rec_len vs file length) -> e_short /
   e_magic / e_version / e_rec_type / e_rec_len; then CRC -> e_crc. The epoch field is read UNAUTHENTICATED only to select the key.
2. Authentication: keyed mode: tag (h computed over the body as found) -> e_tag (17). Signed records (both modes): signature with the key from
   --pubkeys, pinned range -> e_sig (18); a missing or unknown key (incl. the next-epoch key named by EPOCH_START, M1 ruling 3 / A012 F77) is
   e_sig, no new code.
3. Field rules (§4.1, Appendix A reasons) -> e_field / e_reserved / e_reason / e_flag / ...; then chain rules: seq / epoch / handover, prev_link,
   dmethod vs dmode, counters, d_agg, per-code rules, contiguity.
Public (unkeyed) mode: whatever authentication exists goes first: the signature on SIGNED records; EVENT records have none, so for them field
checks run and then the link (prev_link of the next record and the next signature authenticate them). Consequence: a body bit-flip in keyed
mode is e_tag (17), never a field reason (golden vector neg_bitflip_body keyed = e_tag, matching the A011/A012 oracle result); in public mode it
is a field reason or e_link/e_sig at the next authenticated point.
Enum table (A010 F64): the verifier's event-code table is GENERATED from §4.2 (codes.hpp); any code not listed for its rec_type is e_event_code.
Per-code verifier rules and exit effect (A010 F64; complete for v1):
| Code / field | Verifier rule (FAIL reason) | Exit effect |
|---|---|---|
| 1 GENESIS | reason 1-6; bit1 per §4.2; GENESIS fields consistent (e_genesis); d_agg vs --allowlist if given (e_allowlist) | bit1 -> 6 |
| 2 CHECKPOINT | reason 9 level4_entry only while the current level is 4 (M1 ruling 7, adopts the oracle rule; else e_level 39); range, counters non-decreasing, dfail_total == running count of dmethod 4 (saturating) (e_counter); bit2 iff dfail_total > 0; bit1 == GENESIS bit1 (e_flag) | via counters/flags |
| 16 / 17 / 72 | dmethod vs dmode; they advance the forward-seq expectation (rule below); a jump or re-use is never a FAIL (A011 F70); an unexplained jump is the exit-6 qualifier fwd_seq_jump (A012 F74); 72 bytes = groups >= 1 | 16/72: dmethod 4 -> bit2 -> 6; unexplained jump -> 6 (fwd_seq_jump); 17: same jump rule, otherwise no exit effect |
| 64 | §5.3/§5.4 rules | recoveries_total -> 6 |
| 66 | count >= 1; level-4 66 follows a 75 level 4 (e_level); level-4 66 only: subj_first not above E and next 16/17/72 at subj_last + 1 (e_gap_range, F75); other 66 reasons do not touch E (ruling 2) | gaps_total -> 6 |
| 69 | subj_first names an existing FAULT-raising record; reason gap -> it must be a 66 (e_ack_ref) | none |
| 71 | range == the dmethod-4 run, count == run length or saturated, digest == tpmrec(h of last dmethod-1) (e_tpmrec); reason saturated iff count == 2^32-1 (e_reason, ruling 4) | none itself (bit2 already) |
| 73 | count == provisioned NV handle; actor staff | warning commissioning (info) |
| 74 | reasons failed / restored | JSON warnings[] lockdown_failed (no exit change) |
| 75 | levels move by +-1 only, first 75 is level 2 (e_level); a level 4 must be followed by a 66 before any lower level; chain end inside level 4 -> warning gap_open | none itself (entry CKP gaps_total += 1 -> 6) |
| sflags bit1/bit2 | sticky: bit1 constant per chain, bit2 never clears (e_flag) | 6 |
| 3 EPOCH_START | IMMEDIATELY after a CHECKPOINT (A012 F76, e_epoch_handover 27); next-epoch key named in its digest must be in --pubkeys (else e_sig 18, ruling 3 / F77); d_agg zero | no exit effect |
| 22 reason 1 reseed | actor_class 3 + uid (e_actor / e_field); resets E | exit 6 (qualifier reseed; gaps_total += 1, F73) |
| 18-23 (except 22 reason 1), 32-39, 48-52, 65, 67, 68, 70 | field rules and reason table only (68 resets the forward-seq expectation) | no exit effect |
Forward-seq contiguity (A011 F70, replaces the v0.3.3 "contiguous across 16/72/66" rule): records 16, 17 (VOID consumes a forward seq) and 72
advance an expectation E = subj_last + 1. E is RESET (unknown) by a 68 (rollback, sync failure, coverage mismatch, duplicate mismatch), by a 22
with reason reseed (ct01_recv --expect-start or failover to another ct01_recv), by a GENESIS, and at the first record of a verification. A
normal record that does not start at E is NOT a FAIL; since v0.3.5 an UNEXPLAINED jump (no reset in between) is an exit-6 qualifier
`fwd_seq_jump` and a holder alarm (A012 F74; not permanent after pruning, the holders' alarm is the durable trace). M1 ruling 2: ONLY a level-4
66 (reason 3 audit_space) moves E, to subj_last + 1; other 66 reasons neither move E nor FAIL. The rule is a LOWER BOUND for that 66: subj_first
above a known E (fails to cover the hole) is e_gap_range FAIL, and (A012 F75) the next 16/17/72 must start at subj_last + 1 unless a reset
intervenes, else e_gap_range. The reference verifier must align with ruling 2. It cannot attribute frames to a peer (one-stream assumption, §1; F69).
Counter base (A011 F72, verifier note; tests M4): the exact checks "dfail_total == running count" and the gaps/recoveries sums apply only when
verification starts at GENESIS; for a pruned file set or a start at a later checkpoint the base is the first signed record seen, and only
monotonicity + base + observed increments are checked.
Exit-code matrix additions (§8.11, M1): successor chain with later anchor -> 6 (A009 S10 now 6, not 0); truncation + one bit flip ->
FAIL -> successor whose GENESIS records fail reason, last good seq, v_chain, v_tpm (and e_nv_regress when the cut crossed a bump); all-dmethod-4
chain -> 6; level-4 episode with space never returning -> 6 + warning gap_open; level-4 episode with count 0 rebuilt -> still 6 (+1 at entry).
### 6.3 Holder contract (Ruling 2026-11-11, Q1: CLOSED, YES; M4 gate)
Both holders (CT-01 fleet service and customer SIEM collector), over mutual TLS (Q12: TLS 1.3 preferred, 1.2 minimum, pinned holder certs):
1. Record receipt time (only trusted time); keep every checkpoint (seq, epoch, link, sig, nv_export, counters, d_agg) per chain_id.
2. Verify signatures with their own key list (inventory S_0 + Certify-verified S_{e+1}) and pinned epoch ranges.
3. Fork check (Q1): compare (epoch, seq, chain head) across BOTH holders and the device; any mismatch is a visible FAIL (e_fork), not a warning.
   seq, nv_export, recoveries_total and gaps_total never decrease.
4. Alarm on: unexpected GENESIS / chain_id; any successor GENESIS (bit1); recoveries_total, gaps_total or dfail_total increase, bit2 (kept for
   the life of the chain); level changes (75); staleness (> 2 x cadence with records pending); unknown key id; config_mismatch / nv_tampered;
   a 66 count below the last alarmed level-4 count (e_gap_count FAIL).
7. Serve the last checkpoint per chain_id on request (signed, as received) for the device's successor fetch (A009 F49, M4).
5. ACK (seq, link) -> device holder_ack (67).
6. Daily cross-holder comparison (detects one compromised holder).
### 6.4 SIEM export (changed for Q5)
`ct01_audit_verify --export-jsonl`: one JSON line per record, fixed key order, decimal u64, hex hashes, fixed enum names, the link h_n, and
every field EXCEPT the EVENT digest and the tag; no "raw" (v0.2's raw carried the digest). M1 ruling 6 (intended): JSONL is a NON-VERIFYING
export view for search and alerting. Links, tags and signatures are verified ONLY from the binary segments (ct01_audit_verify) or from the
binary signed checkpoints (--checkpoints); the v0.3.4 sentence "a SIEM recomputes links from the exported fields" is withdrawn. JSONL must not
add PHI or per-record digests; d_agg appears only on checkpoint lines. CEF/LEEF mapping (Q7) keeps the same rule.

## 7. Interfaces to CT-01 (no format change)
- Module `audit_chain`: ChainWriter::open (never creates a chain except §5.4 successors), append (returns per §5.2), checkpoint, rotate_epoch,
  close; verify (shared with the CLI and its precedence function); `ct01_audit_admin init | ack-fault`.
- Hooks (COPY of ct01 only): ct01_recv: chain record written before the recvlog COMMIT, one durability barrier = parallel fdatasync of recvlog + chain fds (C1), ACK after both (§5.2); VOID; transfer
  start/end; export intent/outcome; RecvLog::audit() events. ct01d: buffer open (:558), ack_purge intent before :743 / outcome after :758, record
  erase, factory_reset intent before :822's crypto-erase, contingency_audit_line()/AuditCoalesce flushes.
- ct01_recv open-time cross-check: recvlog committed seq vs chain coverage (§5.2 reconciliation); catches inconsistent rollback only.
- Options: ct01d `audit_chain=off|on` + `audit_chain_dir`; ct01_recv `--audit-chain-dir`; off honoured ONLY on unprovisioned devices (§6.1).
  Off-mode test (unprovisioned): no audit_chain directory or file created, no TPM command issued, existing suites unchanged.
- No change to ct01.h, frame v1, CT1F v1, recvlog-1 or buffer formats.

## 8. Tests (synthetic data only)
Golden chain: 64 records, 3 checkpoints, 1 epoch handover, TEST-ONLY keys.
1. Bit-flip every bit: FAIL, or ok_torn_tail only in the last record under §5.3.
2. Truncation scenarios (a007/a008 IDs): S2 -> exit 4, qualifiers [unanchored, torn]; S3 -> 6 with or without anchor; S3b (A1 cuts back
   before event 64, nothing exported) -> 4 off device; on device with NV (M2) -> e_nv_regress if the cut crosses a bump, else 4 (stated limit);
   (from M2, recovery CKP always bumps: S3b on device -> e_nv_regress always, A009 F57); NV rule runs before recovery: a cut that removed the
   bump checkpoint is never 'recovered' (A009 F48 literal-rule case); S3c (pruned below a later anchor) -> 6 via recoveries_total (was 0 in v0.2); S4 -> 4; S5 keyed + anchor -> 0 with records_after_anchor
   reported; S5p -> 5; S6 -> 2 e_behind_anchor; S7b -> 2 e_anchor_mismatch / e_fork; S10 (dir deleted, provisioned) -> successor chain with
   missing_successor, FAULT latched, delivery continues; S10 with config off -> same + config_mismatch; S10 unprovisioned + config off -> off.
3. Reorder, 4. duplicate/replay (incl. old blobs: policy fails at M2), 5. splice (chain_id, cross-epoch, EPOCH_START placement) as v0.2.
6. Recompute without K; wrong key; public mode rebuilt links; key not in --pubkeys; KEY SOURCING (M1, software keys): keys only from
   --pubkeys, a key announced only in EPOCH_START is rejected, signatures outside the pinned epoch range -> e_epoch.
7. Field rules incl. wraps, count fit, actor_uid with actor_class 0/4, len_bucket range 1..65 (66 -> e_field; a > 4 GiB session total -> bucket 34, A009 F47), sflags bits 1-2 sticky and 3-7 zero, dfail_total vs bit2, counters decreasing (e_counter), codes 71-75 in the parser tests (A010),
   and the Q9 test: no per-frame or per-group field carries an exact length (§4.4).
   C3 tests: (a) transfers of 1, 31, 32, 33 frames: bytes == 0 below 32, exact at >= 32 (threshold in frames, not bytes); (b) every 22/23
   written by the writer has ts_ms and mono_ms multiples of 1000 and end ts >= floor(last code-16 ts / 1000) * 1000 (A009 F54; property test over random clocks); a
   hand-built 23 with ts_ms % 1000 != 0 -> e_ts_gran; (c) reconnect replay: overlapping second session gets bucket only; a hand-built
   overlapping exact total -> e_xfer_overlap; (d) differencing check: from the exported JSONL of a synthetic run, no exact frame or group
   length is derivable as a difference of two exported totals.
   C4 tests: dmethod 0 / 5-255 -> e_dmethod; dmethod 1 with zero digest, dmethod 2/4 with non-zero digest -> e_dmethod; dmode 1 chain with a
   dmethod 2 record, dmode 2 chain with dmethod 1 or 4 -> e_dmethod; CHECKPOINT dmode != epoch dmode -> e_dmode; d_agg recomputed by the single §4.3 rule in both dmodes (wrong d_agg -> e_dagg, A011 F71);
   mode change only via EPOCH_START (accepted) or successor GENESIS; config edited mid-epoch -> no change until rotation; TPM2_HMAC fault
   injection -> dmethod 4 + FAULT digest_failed + group ACKed; JSON digest counts; Release binary has no software D_e symbol.
8. Crash injection (>= 1,000 kill -9 per point): append points, roll, recovery steps, each rotation step incl. the §3.4 open-time path
   (crash between 3 and 4: signature checked, increment, then tag), NV order points (after CHECKPOINT fsync before NV_Increment; after
   increment), successor-chain steps (a)-(c), recv group points around the chain write / COMMIT / each of the two fdatasyncs (0 ACKed without record at ladder levels 1-3, 0 gaps; level 4 per §8.9).
9. Failure injection: ENOSPC / short write at every byte, reserved-space exhaustion of the buffer FS (chain unaffected), BROKEN writer;
   fdatasync EIO injection (A009 F51): no retry on that fd, successor in a fresh segment, in-flight group re-recorded then ACKed; recvlog
   fdatasync error: no ACK, 68 + replay; dir-fsync-before-first-ACK ordering (F55); syncfs fallback refused when the open checks fail (F55);
   reserve shrink / punch-hole -> reserve_tampered (F62); level-3 crash -> 72 rebuilt from the slot (F59); level-4 entry CKP present when space
   never returns; recvlog tail cut at a COMMIT during level 4 -> count from the counter file, not under-counted (F61).
   C5 ladder (small x86 partition): an A1 file fills the partition -> level 2, reserve untouched, ACKs continue; reserve 50% -> level 3
   records 72; reserve exhausted -> level 4, 0 ACKs withheld, counts exact; space freed -> record 66 with the counted groups, next CHECKPOINT
   gaps_total += n, verifier exit 6; kill -9 at level 4 -> gap rebuilt from recvlog (68 + 66), 0 delivered groups unaccounted; fault_ack
   reason gap is written and clears only that FAULT; > 24 h -> gap_24h alarm (FakeClock); no config value restores backpressure.
   C6: uncommissioned + phEnable 1 -> all 'F'; commissioned + lockdown fails -> delivery continues, FAULT, seal/AK/rotation refused, retry,
   restored record; NV_commissioned cannot be set without K_comm, cannot be cleared (swtpm, M2); deleting chain/config keeps commissioned.
   C7: HMAC fault for k groups -> k x dmethod 4, then record 71 with range/count k and last good link; tampered 71 -> e_tpmrec.
10. Integration (copy of ct01): off-mode (unprovisioned); chain on: write-ahead traces, phi_scan, canary, F27 regression, Q5 export test (no
    digest or tag in JSONL; d_agg only in checkpoints), delivery continues on every FAIL scenario (G7).
11. Exit-code matrix (M1): every row of §6.2 incl. V0 (intact, no anchor -> 4), V0a (anchor -> 0), S2, S3, S3b, S3c, S5, S5p, S8, S9,
    multiple-qualifier precedence, 7-9 never emitted; identical results from the device self-check path and the CLI.
12. TPM (M2, swtpm, "not hardware"): F53 lockdown order (HierarchyChangeAuth then HierarchyControl) after CLEAR and STATE, phEnable 1
    after a raw resume without the hook (reference behaviour); F50 TPM2_Clear refused after ClearControl; F63 redefined NV handle detected by
    the name check; PolicySigned replay and expiration cases; noDA on D_e/S_e; F56 fresh key set Certified after deleted blobs; AK credential activation with the swtpm EK CA; Certify; software-key announcement rejected; PolicyNV
    revocation of restored blobs; NV counters created non-ORDERLY and N1'/N1''/N2'/N4 cases; command trace shows salted, encrypted sessions for
    Unseal, Sign, HMAC and NV writes and no empty-auth use; platform hierarchy: phEnable == 0 via HierarchyControl after the boot oneshot, after a power cycle (Startup CLEAR) AND after a resume (Startup STATE, incl. a failed STATE falling back to CLEAR); Release ct01d data path blocked when phEnable == 1;
    after a simulated TPM reset (F45 note); TPM2_HMAC per group latency recorded (labelled).
13. KATs: RFC 4231, RFC 5869, FIPS 180-4, Wycheproof ecdsa_secp256r1_sha256 + CAVP SigVer. Golden vectors frozen with MANIFEST; x86 = aarch64-qemu.

## 9. Fuzzing (libFuzzer, ASan+UBSan)
Targets 1-7 as v0.2 (verify, mutate, diff, recover, jsonl_export, pubkeys_parse, anchor_parse) plus 8. fuzz_checkpoints (arbitrary
--checkpoints files and two-holder fork comparison). Target 3 differential oracle: an independent naive verifier. A008 §7 item 4 commits to delivering it at the
start of M1. An earlier independent model verifier must be updated to v0.3 or replaced; proposed path:
audit_chain_naive_verify.py. Gates: >= 1 h continuous per target, 0 findings; >= 12 h cumulative before M4.

## 10. HIPAA impact (no compliance claim)
- Touches audit controls and audit-record integrity. A HIPAA review would look at the areas of 45 CFR 164.312(b) and 164.312(c)(1);
  this design does not claim either. No pilot use and no "tamper-evident" claim before M4 GO.
- Decisions folded in (2026-11-11): Q5 keyed digest under conditions (§4.3), Q6 keep delivering +
  successor + latched FAULT (§5.4-5.5), Q8 checklist item partial (§0), Q9 bucketed lengths (§4.4), Q10 staff uid in clear with conditions
  (§4.4), Q2 no escrow (§3.2), Q12 mTLS (§0, §6.3).
- Pre-pilot prerequisites created by this design: uid-to-person registry (access-controlled, outside the log); TLS transport ADR + holders;
  TPM hardware + session encryption + platform-hierarchy lockdown; secure boot.

## 11. Risks
- No anchor until holders (M4); on-device NV anchor only hourly granularity from M2.
- C1 parallel fdatasync cost with audit on is UNMEASURED (M4 gate); syncfs fallback flushes the whole log filesystem.
- C5 ladder: level 4 delivers with count-only audit for the episode (bounded, signed afterwards, 24 h escalation); reserve size UNMEASURED.
- C6: a post-commissioning lockdown failure leaves phEnable = 1 (platform hierarchy usable by A2) while delivering; bounded by alarm, block of seals/AK/rotation and the 24 h review.
- NV_commissioned relies on the device's own (unattested) phEnable report at the ceremony.
- TPM2_HMAC per recv group may not fit the throughput gates (published Sign 25-69 ms vs 20 ms/group; HMAC unpublished): M5 go/no-go, options O1-O3, C8 (§2).
- Signed layout change 308 -> 316 B lands while M1 parsing is in progress (parser constants, naive-verifier spec).
- Level-3 crash loses the window's digest (rebuilt 72 = dmethod 4, exit 6); level 4 count relies on K_e (A2 can forge it during [t0, t1]).
- A2 / persistent compromise; copied R^t bytes; NV wear (datasheet before M4, measurement M5); platform hierarchy reset behaviour (F45 note).
- Successor-chain automation could hide repeated tampering in noise: holders alarm on every successor; FAULT needs a staff ack.
- Clock evidence weak by design; outputs label it writer_reported.

## 12. Milestones (separate tree; no merge, push or ct01 edit without the project owner's routing and the user's go-ahead)
- M0: schema freeze (v0.3.3 layout: EVENT 180 / SIGNED 316, codes.hpp from §4.2, sflags bits 0-2, Q9/Q10 settled), reference model + golden
  vectors. GO: independent diff-check of v0.3.3 against the A009/A010 pre-freeze set (F47, F48, F49, F51, F52, F60, F61, F64).
- M1 (software keys): writer + verifier + successor/FAULT logic (G7) + exit-code matrix §8.11 (incl. S3b, S3c, V0). GO: §8.1-8.11, 8.13 green
  (GCC, ASan+UBSan, aarch64-qemu); >= 1,000 kills per point, 0 unverifiable prefixes, 0 lost returned appends; KEY-SOURCING tests pass (keys
  only from --pubkeys, pinned ranges); differential agreement with the independent naive verifier (§9; delivered at M1 start); same precedence on
  device path and CLI; x86 dev-box append cost reported (labelled).
- M2 (swtpm, "not hardware"): §8.12 all pass. GO: AK mandatory + credential activation with swtpm EK CA (Q13); S_e/D_e templates and policies
  (Q3, sessions); NV non-ORDERLY + F39 order/open rule; PolicyNV revocation; platform-hierarchy oneshot leaves phEnable == 0 after a power cycle
  (Startup CLEAR) AND a resume (Startup STATE) (F45, C2); F50/F63 (ownerAuth/lockoutAuth random, disableClear, NV name checks, pinned PolicySigned), F53 lockdown order on CLEAR and STATE, F56 successor keys, F57 always-bump; C6: NV_commissioned policy (set-only, K_comm), rule 1 'F' pattern before commissioning, rule 2 deliver + FAULT + blocked seal/AK/rotation after; TPM2_HMAC latency recorded; review of TPM code; NV handle ADR (Q14).
- M3: CLI (incl. --checkpoints), JSONL, admin tool; fuzz 1-8. GO: >= 1 h each, 0 findings, >= 12 h cumulative; phi_scan clean.
- M4: hooks in a COPY of ct01 + both holders over mutual TLS (transport-auth ADR, scheduled by DevOps, Q12). GO: Durability barrier = parallel fdatasync of both fds (C1), dedicated log partition + C5 ladder levels 0-4 and GAP bounds tested (§8.9 on x86 with a small partition), C5 hardening (0700 mount, resuid
  reserved blocks, recvlog project quota, per-device rate limits), F59 aggregate slot, F62 reserve protection, F54 tests, F55 ordering and syncfs
  checks, F58 read-only rootfs + compiled-in dir + allowlist hash, holder fetch-last-checkpoint (F49).
  Q1 holder contract incl. 3-way fork check; Q11 SIGN-OFF conditions: CT01D gates re-run with audit ON (--log-dir median >= 25 MB/s and worst
  >= 20 MB/s, CT01D.md:634) and kill -9 with 0 lost and 0 gaps, on x86 now (Pi 5 later, M5); TPM datasheet endurance checked (Q14);
  Q5 conditions still met; G7 demonstrated (FAIL and missing-chain scenarios keep delivering); design review.
  NO-GO if the gates fail with audit on.
- M5 (blocked on TPM purchase): hardware latency (Sign, HMAC, NV), platform hierarchy on hardware, Pi 5 gate re-run. EXPLICIT GO/NO-GO for
  dmode 1 with one TPM2_HMAC per group (§2, C8): NO-GO unless p99 group latency fits 20 ms with checkpoint signing running. GO for pilot only after
  a HIPAA review AND the pre-pilot items (§10) exist.

## 13. Tie-in to the pre-pilot gap
Would close, once M4 passes and a HIPAA review verifies (not before, and no "tamper-evident" claim before then): the tamper-evidence half of
HIPAA_CHECKLIST §4 :62 for events CT-01 emits today, against A1; truncation/rollback/replacement detection with holders, and on device at NV
granularity; a SIEM export format and an independent verifier. Partly addresses the recvlog high-water item (inconsistent rollback only).
Does NOT close: network forwarding without the TLS ADR; events no code emits; NTP time; retention; A2 compromise; physical attackers without
secure boot; TPM hardware; the ignored-error behaviour of the existing text audit logs; the uid-to-person registry.

## 14. Findings traceability (A007 F24-F38 closed per A008 §2; A008 below)
| Finding | Sev | Where addressed | Status |
|---|---|---|---|
| F24-F38 (A007) | — | see DESIGN.v0.2.md §14; A008 §2 confirms all CLOSED | closed (A008) |
| F39 NV order and anchor existence | MEDIUM | §3.5 (order, open rule, definition, hourly local bumps from M2, non-ORDERLY), §1 G3, §8.8, §8.12, §12 M2 | fixed in text; tested M2 |
| F40 config off-switch | MEDIUM | §6.1 (TPM-resident requirement, config_mismatch, init refuses without predecessor), §4.2 event 70, §8.2 S10 variants | fixed in text; tested M2/M4 |
| F41 FAIL halts delivery | MEDIUM | G7, §5.4 successor chain, §5.5 latch, §6.1 no refuse-to-start, §5.1 reserved space, Q6 decision | fixed in text; M1 condition |
| F42 ok_recovered not permanent | LOW | §4.1 recoveries_total/gaps_total, §6.2 exit 6 rule, §6.3.4, §8.2 S3b/S3c | fixed; S3b limit stated |
| F43 clock fields | LOW | §1 time, §4.1 writer-reported + sflags.safe, §6.2 JSON label | fixed |
| F44 rotation order | LOW | §3.4 steps 1, 3, 5 and open-time crash path | fixed |
| C3 transfer totals / timestamps (compliance) | — | §4.1 ts rows, §4.4, §6.2 e_ts_gran/e_xfer_overlap, §8.7 | fixed |
| C4 digest fallback (compliance) | — | §4.1 dmethod/dmode/digest/d_agg rows, §4.3 conditions 1-3, §6.2 digest JSON, §8.7 | fixed; C7 ruled (record 71) |
| F45 platform hierarchy | LOW | §1, §3.1 (Ruling + C2: per-boot oneshot, HierarchyControl, phEnable check, resume, spec citation), §8.12, §12 M2/M5 | fixed; C6 ruled (§3.1) |
| F41.4 reserved space (re-done for C1) | MEDIUM | §5.1 dedicated log filesystem + fallocate, §5.2 barrier, §5.6 C5 ladder + GAP bounds, §8.9 | fixed; C5 ruled |
| F47 len_bucket range | MEDIUM (A009) | §4.1 len_bucket 1..65, §4.4 justification, §8.7, layout_v0_3_3.py | fixed (pre-freeze) |
| F48 counter-acknowledged vacuous; NV vs recovery order | MEDIUM (A009) | §3.5 bump checkpoint + open sequence, §5.4 recovery precondition, §8.2 | fixed (pre-freeze) |
| F49 successor exits 0 | MEDIUM (A009) | §4.1 sflags bit1, §4.2 GENESIS fields + 66 count >= 1, §5.4 (a), holder fetch §5.4/§6.3.7, §6.2 exit 6 + matrix | fixed (pre-freeze); holder fetch M4 |
| F50 TPM2_Clear off-switch / DoS | MEDIUM (A009; worse per A010) | §1, §3.1 hardening (ownerAuth/lockoutAuth, disableClear, Release never off), §6.1 | text-only; M2 gate; residual C9 |
| F51 non-space append errors; fdatasync retry | MEDIUM (A009) | §5.1 write-error rule, §5.2 fail-closed row, §8.9 | fixed (pre-freeze) |
| F52 KEYED_FAILED no exit / DA lockout | MEDIUM (A009) | §4.1 sflags bit2, §3.1 noDA, §4.3 bounded retries, §6.2 exit 6 | fixed (pre-freeze) |
| F53 phEnable set on every Startup | LOW (A009) | §1, §3.1 correction (credited) + lockdown order + ct01d self-apply, §8.12 | text-only; M2/M5 |
| F54 C3 test text, overlap mark, leave-one-out | LOW (A009) | §4.4, §8.7 | text-only; tests M4 |
| F55 dir fsync / fchmod ordering, syncfs checks | LOW (A009) | §5.1, §5.2, §8.9 | text-only; M4 |
| F56 successor key set | LOW (A009) | §3.1 successor keys, §5.4 (a) | text-only; M2 |
| F57 always bump on rare events; S3b | LOW (A009) | §1 limit text, §3.5 exceptions, §5.4, §8.2 | text-only; M2 |
| F58 rootfs, default dir, allowlist hash | LOW (A009) | §1 assumptions, §4.1 GENESIS d_agg + allowlist hash, §4.4 registry rule, §6.1 default dir | text-only; M4 |
| F59 level-3 vs 2 s ACK deadline | MEDIUM (A010) | §5.6 level 3 aggregate slot + rebuild, §4.2 72 | text-only; M4 |
| F60 C7 running totals not in layout | MEDIUM (A010, pre-freeze) | §4.1 dfail_total @176 + ext_reserved @180 (SIGNED 316), §4.3 (iii), layout_v0_3_3.py | fixed (schema change) |
| F61 level 4 RAM-only / under-count | MEDIUM (A010, pre-freeze) | §5.6 control slice, entry 75 + CKP (gaps_total += 1), counter file §5.2, e_gap_range/e_gap_count | fixed (pre-freeze) |
| F62 reserve shrink | MEDIUM (A010) | §5.6 reserve protection + detection | text-only; M4 |
| F63 NV_commissioned redefine, PolicySigned, K_comm | MEDIUM (A010) | §3.1 hardening | text-only; M2 |
| F64 exit/verifier rules 66/69/71/72/74/75 | LOW (A010, pre-freeze) | §6.2 per-code table + matrix additions, §4.2 | fixed (pre-freeze) |
| F65 incident review at level-4 entry | LOW (A010) | §5.6 HIPAA bounds | deferred (C12) |
| F66 numeric reason tables | MEDIUM (A011) | Appendix A (codes.hpp: e_* 0-40, per-code reasons, exit effects), §4.1 reason row, §4.2 GENESIS zero rule, codes_tables_v0_3_4.py | fixed (before M1 GO) |
| F67 level-4 entry ordering | LOW (A011) | §5.6 level 4 ordering sentence; C13 | fixed in text |
| F70 contiguity false FAILs | MEDIUM (A011) | §6.2 contiguity rule (17 included; resets on 68 / 22 reseed / GENESIS; lower bound for 66 only), §4.2 66/72 rows, §5.6 | fixed (before M1 GO) |
| F71 d_agg defined twice | MEDIUM (A011) | §4.3 single rule (every EVENT digest), §4.1 d_agg row, C4 text withdrawn, layout_v0_3_4.py | fixed (before M1 GO) |
| F68 control-slice budget, counter custody, frames in 66 | LOW (A011) | DEFERRED (below) | M4 |
| F69 single instance, recvlog lock, peer identity, conflicting duplicates | LOW (A011) | DEFERRED (below); reason 68.4 duplicate_content_mismatch already numbered in Appendix A | M4 (peer identity after Q12) |
| F72 counter base on pruned files | LOW (A011) | §6.2 verifier note now; tests DEFERRED | M4 |
| M1 rulings 0-7 (implementation questions) | — | §6.2 check order (0), §4.1 key_id (1), §6.2 contiguity (2), §6.2 EPOCH_START/e_sig (3), §4.2 71 (4), §4.2 68/74 names (5), §6.4 JSONL (6), §6.2 CKP reason 9 (7) | written in (normative) |
| F73 reseed unauthorized and silent | MEDIUM (A012) | §4.2 22 row + reseed rule, §4.1 subj_last exception, §6.2 table, Appendix A (22 reason 1 FAULT-raising, exit 6) | text now; M4 gate |
| F74 unexplained fwd_seq_jump | LOW (A012) | §6.2 contiguity + exit-6 qualifier + holder alarm | fixed in text |
| F75 e_gap_range high end | LOW (A012) | §6.2 contiguity, layout_v0_3_5.py | fixed in text |
| F76 EPOCH_START immediately after CHECKPOINT | LOW (A012) | §4.1 epoch row, §6.2 table (e_epoch_handover) | fixed in text |
| F77 unknown pubkey code | LOW (A012) | §6.2 check order step 2 (e_sig, no new code) | fixed in text |
| F46 exit-code hygiene | LOW | §6.2 (stable API, 7-9 reserved, 3<=rc<=6, records_after_anchor, no whitelisting 4, shared precedence), §8.11 | fixed |

Deferred list (A011; text owner: design, implementation: the library, gate shown):
- F68 (M4): control slice ONLY for ladder-control records (64-75 when written by the ladder) + the level-4 entry/exit CHECKPOINTs; periodic
  CHECKPOINTs suspended at level 4; budget rule and alarm at 50% of the slice; counter file root-owned and fd-passed like the reserve (§5.6
  F62); 66 at level 4 carries frames in `bytes` (verifier: <= range length). Arithmetic (a011 slice_sizing.log): 1 MiB = 3,318 CHECKPOINTs
  (9.2 h at 10 s) or 5,825 EVENT records.
- F69 (M4): chain lock busy = FATAL for the second process (exit, no listen), an exception to G7 because the first instance records; flock on
  the recvlog directory in the M4 copy; records 22/23 carry a peer-identity pseudonym (act kind 3) after the Q12 transport ADR; a duplicate
  seq with different content -> FAULT + 68 reason duplicate_content_mismatch. Pre-existing ct01 facts (A011, read-only): ct01_recv serves one
  client at a time without peer authentication (main.cpp:1245, :1283), one global expected seq (:1248-1251), duplicates re-ACKed (:16, :261).
- F72 (M4): counter-base tests for pruned sets and later-checkpoint starts (rule already in §6.2).
- Earlier gates unchanged: M2 F50, F53, F56, F57, F63; M4 F54, F55, F58, F59, F62; before pilot F65 (C12).

## Open questions (owners decide)
Closed in v0.3 (marked where folded in): Q1, Q2, Q3, Q4, Q12, Q13, Q14 (Rulings 2026-11-11; Q2 and Q12
also compliance decisions); Q5, Q6, Q8, Q9, Q10 (Decisions 2026-11-11).
Q11: approved in principle; SIGN-OFF is an M4 gate (conditions §12 M4). Remains a gate, not an open design question.
Still open:
- Q7 (Product, low priority) SIEM field mapping beyond JSONL. Recommendation: JSONL is fine; any mapping keeps fixed enums, no free text.
  Proposed default: JSONL only.
Clarifications (they do not reopen the rulings). C1-C7 all ruled. New in v0.3.3 (from A009/A010): C8-C12 OPEN; new in v0.3.4: C13 OPEN (A012 recommendation noted); Q7 still open.
| # | Owner | Item | Status |
|---|---|---|---|
| C1 | Engineering | Meaning of "same group commit/fsync" for two files | CLOSED (Ruling 2026-11-11): one durability barrier per group, parallel fdatasync of both fds, ACK after both; syncfs fallback (kernel >= 5.8, two-log filesystem); dedicated log partition, fallocate (§5.1, §5.2); its watermark backpressure is REPLACED by C5 |
| C2 | Engineering | Platform lockdown every boot? | CLOSED (Ruling 2026-11-11): per-boot oneshot before networking and ct01d, HierarchyControl preferred, Release phEnable check, maintenance-mode boot for firmware; resume also covered after the spec check (§3.1) |
| C3 | Compliance | Transfers under 32 frames keep bucketed totals (Q9 reading) | CLOSED (Decision 2026-11-11): CONFIRMED, threshold in frames, plus the timestamp-granularity rule (§4.4) |
| C4 | Compliance | D_e in the TPM; explicit fallback | CLOSED (Decision 2026-11-11): ACCEPTABLE with conditions (1) explicit dmethod/dmode, (2) genesis/epoch config, never a runtime switch, (3) TPM HMAC or no digest; export without digest/tag/raw confirmed (§4.3) |
| C5 | CT-01 (joint) | Full log filesystem vs Q6 | CLOSED (formal joint ruling 2026-11-11): ladder (e), (b), (d), bounded (c) is THE behaviour, ACKs never stop for audit storage, GAP bounds; 'audit full' wire code pre-pilot via transport ADR, not a blocker, not in demo (§5.6) |
| C6 | Engineering, with compliance endorsement | phEnable check vs G7 | CLOSED (joint ruling 2026-11-11): before commissioning kek_unavailable pattern; after, deliver + latched FAULT + alarm + backoff, block seals/AK/rotation; no plaintext or software keys; > 24 h incident review; NV_commissioned set-only bit + record 73 (§3.1) |
| C7 | CT-01 | Runtime TPM2_HMAC failure | CLOSED (ruled 2026-11-11): dmethod 4 KEYED_FAILED + latched FAULT, delivery continues; record 71 tpm_recovered chains from the last good link (§4.3) |
| C8 | CT-01 | TPM latency: if M5 shows one TPM2_HMAC per group does not fit 20 ms, pick O1 batched HMAC (dmethod 5), O2 async Sign, or O3 dmode 2 (§2) | OPEN (decide by M5) |
| C9 | CT-01 | After a TPM Clear on a commissioned device (NV_commissioned gone): keep C6 rule 1 (all 'F'), or treat a verified record 73 under the inventory S_0 key as proof of commissioning and use rule 2 (§3.1) | OPEN (by M2) |
| C10 | Engineering | ownerAuth / lockoutAuth custody: two-person sealed in the key ceremony (PROPOSED) or discarded (§3.1) | OPEN (by M2) |
| C11 | Engineering | Acknowledge that A009 F53 makes random platformAuth + HierarchyControl both mandatory, auth first (amends C2's "prefer HierarchyControl") | OPEN (by M2) |
| C13 | CT-01 | A011 F67: if the level-4 entry (75 + signed CHECKPOINT + NV bump) keeps failing (control slice unwritable, TPM Sign failing), keep withholding ACKs (PROPOSED, the fail-closed reading), or deliver count-only with alarm only; the first conflicts with C5 "ACKs never stop for audit storage" in this narrow case (§5.6). A012 recommends an explicit time bound: after N s of failed entry fall back to count-only with a holder alarm (the counter file is durable anyway). Not decided | OPEN (by M4) |
| C12 | Compliance | A010 F65: incident review at level-4 entry instead of after 24 h (gap_24h kept as second escalation) (§5.6) | OPEN (before pilot) |

## Appendix A. codes.hpp (NORMATIVE; FROZEN at M0 with the v0.3.3 bytes; A011 F66; generated from tests/spec/codes_tables_v0_3_5.py, which asserts the numbers and names equal v0.3.4; never renumbered, append only)
Enums with fixed numbers: rec_type 1 GENESIS, 2 EVENT, 3 CHECKPOINT, 4 EPOCH_START; actor_class 0-4 (§4.1); dmethod 1-4 (5 reserved); dmode 1-2;
sflags bit0 safe, bit1 successor, bit2 digest_failed; exit codes 0-6 (7-9 reserved, §6.2).
A.1 FAIL reasons (e_*; JSON `reason`, GENESIS.count for reason 3; 0 = none):
| value | name | value | name | value | name | value | name |
|---|---|---|---|---|---|---|---|
| 0 | e_none | 11 | e_field | 22 | e_short | 33 | e_tpmrec |
| 1 | e_magic | 12 | e_flag | 23 | e_no_genesis | 34 | e_genesis |
| 2 | e_version | 13 | e_dmethod | 24 | e_behind_anchor | 35 | e_allowlist |
| 3 | e_rec_type | 14 | e_dmode | 25 | e_anchor_mismatch | 36 | e_gap_range |
| 4 | e_event_code | 15 | e_ts_gran | 26 | e_ckpt_range | 37 | e_gap_count |
| 5 | e_rec_len | 16 | e_link | 27 | e_epoch_handover | 38 | e_ack_ref |
| 6 | e_reason | 17 | e_tag | 28 | e_unexpected_chain_id | 39 | e_level |
| 7 | e_actor | 18 | e_sig | 29 | e_file_order | 40 | e_dagg |
| 8 | e_reserved | 19 | e_crc | 30 | e_fork |  |  |
| 9 | e_seq | 20 | e_counter | 31 | e_nv_epoch |  |  |
| 10 | e_epoch | 21 | e_nv_regress | 32 | e_xfer_overlap |  |  |
A.2 Event codes, per-code reason values (`reason` u16 @12; any value not listed = e_reason) and exit effect:
| code | rec_type | name | reasons (value name) | exit effect |
|---|---|---|---|---|
| 1 | GENESIS | genesis | 1 provisioning, 2 operator_init, 3 fail_successor, 4 missing_successor, 5 predecessor_unknown, 6 tpm_cleared | bit1 set (reasons 3-6, or 2 on a provisioned device) -> 6 |
| 2 | CHECKPOINT | checkpoint | 1 cadence_time, 2 cadence_count, 3 shutdown, 4 pre_export, 5 recovery, 6 chain_creation, 7 epoch_pre, 8 epoch_post, 9 level4_entry, 10 level4_exit, 11 successor | via counters/flags it carries -> 6; reason 9 requires level 4 (e_level) |
| 3 | EPOCH_START | epoch_start | 1 scheduled, 2 tpm_or_firmware_change, 3 post_compromise, 4 dmode_change | no exit effect |
| 16 | EVENT | recv_group_delivered | 0 normal, 1 recovered_unacked, 2 rerecorded_after_chain_fail | dmethod 4 -> bit2 -> 6 |
| 17 | EVENT | recv_void | 0 normal | no exit effect |
| 18 | EVENT | recv_export_intent | 0 intent | no exit effect |
| 19 | EVENT | recv_export_outcome | 1 ok, 2 failed | no exit effect |
| 20 | EVENT | recv_log_fault | 1 rollback_truncate_failed, 2 seal_failed, 3 io | no exit effect |
| 21 | EVENT | recv_log_torn_tail | 0 normal | no exit effect |
| 22 | EVENT | recv_transfer_start | 0 normal, 1 reseed | reason 1 reseed -> 6 (qualifier reseed; gaps_total += 1 in the next CHECKPOINT, A012 F73); reason 0: no exit effect |
| 23 | EVENT | recv_transfer_end | 0 normal | no exit effect |
| 32 | EVENT | buffer_open | 0 normal | no exit effect |
| 33 | EVENT | ack_purge_intent | 0 intent | no exit effect |
| 34 | EVENT | ack_purge_outcome | 1 ok, 2 failed | no exit effect |
| 35 | EVENT | record_erase_intent | 0 intent | no exit effect |
| 36 | EVENT | record_erase_outcome | 1 ok, 2 failed | no exit effect |
| 37 | EVENT | factory_reset_intent | 0 intent | no exit effect |
| 38 | EVENT | factory_reset_outcome | 1 ok, 2 failed | no exit effect |
| 39 | EVENT | buffer_fault | 1 fill_warn, 2 outage_warn, 3 fill_fault, 4 outage_fault, 5 full, 6 retention, 7 crypto, 8 io, 9 tpm, 10 kek_unavailable, 11 mem_lock | no exit effect |
| 48 | EVENT | contingency_pass_through | 0 normal | no exit effect |
| 49 | EVENT | nack_gap_replay | 0 normal | no exit effect |
| 50 | EVENT | void_acked | 0 normal | no exit effect |
| 51 | EVENT | kek_unavailable | 0 normal | no exit effect |
| 52 | EVENT | mem_lock_failed | 0 normal | no exit effect |
| 64 | EVENT | chain_torn_tail_recovered | 0 normal | recoveries_total -> 6 |
| 65 | EVENT | chain_predecessor | 1 old_chain, 2 holder_checkpoint, 3 unknown | no exit effect |
| 66 | EVENT | chain_gap | 1 fail_successor, 2 unrecordable, 3 audit_space, 4 count_unknown | gaps_total -> 6 |
| 67 | EVENT | holder_ack | 0 normal | no exit effect |
| 68 | EVENT | recv_coverage | 1 coverage_mismatch, 2 group_rolled_back, 3 recvlog_sync_failed, 4 duplicate_content_mismatch | no exit effect |
| 69 | EVENT | fault_ack | 1 fault, 2 gap | no exit effect |
| 70 | EVENT | config_mismatch | 1 config_off, 2 dir_missing, 3 nv_tampered | no exit effect |
| 71 | EVENT | tpm_recovered | 0 normal, 1 saturated | no exit effect |
| 72 | EVENT | recv_groups_compacted | 1 normal, 2 rebuilt | dmethod 4 (incl. rebuilt) -> bit2 -> 6 |
| 73 | EVENT | commissioning_verified | 0 normal | none (JSON info) |
| 74 | EVENT | lockdown | 1 failed, 2 restored | none (JSON warning lockdown_failed) |
| 75 | EVENT | audit_space_level | 1 level1, 2 level2, 3 level3, 4 level4, 5 reserve_tampered | none itself (level-4 entry CKP gaps_total += 1 -> 6); gap_open warning |
FAULT-raising (valid targets of 69 reason 1 fault; 69 reason 2 gap must name a 66): 1 reasons 3-6, 20, 21, 22 reason 1 (v0.3.5, F73), 39, 51,
52, 64, 66, 68, 70, 74 reason 1, 75 reasons 2-5, and any EVENT with dmethod 4 [e_ack_ref]. 39 reasons equal ct01_buf_reason
(ct01/src/include/ct01/ct01_buffer.h:40-53). Checkpoint reasons 5 (recovery), 9 (level4_entry), 11 (successor) and the first CHECKPOINT after
70 or after bit2 is set always bump NV_export (§3.5). JSON detail strings (fwd_seq_jump, reseed, gap_open, ...) are not enum values.
