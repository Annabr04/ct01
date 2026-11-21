// audit_chain record schema: DESIGN v0.3.4 sections 4.1 / 4.2 / 6.2 (bytes: tests/spec/layout_v0_3_3.py,
// unchanged in v0.3.4 per tests/spec/layout_v0_3_4.py). DESIGN.md sha256 79a99e64446a207d... (v0.3.4, 925 lines).
//
// THE ONE PLACE for every layout constant, enum, label, mask, range and per-event-code
// rule. SCHEMA FROZEN: review A011 (2026-11-11 ET) declared the v0.3.3 bytes final
// (EVENT 180 B, SIGNED 316 B, these offsets, sflags bits 0-2, DS labels, 56 B pre-image).
// Numeric tables (F66) frozen in DESIGN v0.3.4 Appendix A -> generated include/ct01/codes.hpp.
// No other file hard-codes an offset, size, label, mask or range.
//
// codes.hpp is produced by tests/tools/gen_codes.py (CTest codes_vs_design checks it).
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "ct01/codes.hpp"

namespace ct01::audit::layout {

// ---- sizes (layout_v0_3_3.log: body 144 | EVENT 180 | signed body 216 | SIGNED 316) ----
inline constexpr std::size_t kHashSize = 32;
inline constexpr std::size_t kChainIdSize = 16;
inline constexpr std::size_t kTagSize = 32;
inline constexpr std::size_t kSigSize = 64;        // ECDSA P-256 r || s, big-endian
inline constexpr std::size_t kCrcSize = 4;
inline constexpr std::size_t kBodySize = 144;      // common body
inline constexpr std::size_t kSignedBodySize = 216;
inline constexpr std::size_t kEventRecordSize = kBodySize + kTagSize + kCrcSize;                    // 180
inline constexpr std::size_t kSignedRecordSize = kSignedBodySize + kTagSize + kSigSize + kCrcSize;  // 316
inline constexpr std::size_t kMinRecordSize = kEventRecordSize;   // torn-stub threshold, unparseable header (5.3)
inline constexpr std::size_t kMaxRecordSize = kSignedRecordSize;
inline constexpr std::size_t kHeaderParseSize = 12;               // magic..rec_len

// ---- common body offsets ----
inline constexpr std::size_t kOffMagic = 0;        // 4
inline constexpr std::size_t kOffVersion = 4;      // 1
inline constexpr std::size_t kOffRecType = 5;      // 1
inline constexpr std::size_t kOffEventCode = 6;    // 2
inline constexpr std::size_t kOffRecLen = 8;       // 4
inline constexpr std::size_t kOffReason = 12;      // 2
inline constexpr std::size_t kOffActorClass = 14;  // 1
inline constexpr std::size_t kOffDmethod = 15;     // 1
inline constexpr std::size_t kOffSeq = 16;         // 8
inline constexpr std::size_t kOffEpoch = 24;       // 4
inline constexpr std::size_t kOffLenBucket = 28;   // 1
inline constexpr std::size_t kOffSflags = 29;      // 1
inline constexpr std::size_t kOffDmode = 30;       // 1
inline constexpr std::size_t kOffReserved1 = 31;   // 1
inline constexpr std::size_t kOffTsMs = 32;        // 8
inline constexpr std::size_t kOffMonoMs = 40;      // 8
inline constexpr std::size_t kOffSubjFirst = 48;   // 8
inline constexpr std::size_t kOffSubjLast = 56;    // 8
inline constexpr std::size_t kOffCount = 64;       // 4
inline constexpr std::size_t kOffActorUid = 68;    // 4
inline constexpr std::size_t kOffBytes = 72;       // 8
inline constexpr std::size_t kOffDigest = 80;      // 32
inline constexpr std::size_t kOffPrevLink = 112;   // 32
// ---- signed extension ----
inline constexpr std::size_t kOffNvExport = 144;        // 8
inline constexpr std::size_t kOffTpmClockMs = 152;      // 8
inline constexpr std::size_t kOffTpmResetCount = 160;   // 4
inline constexpr std::size_t kOffTpmRestartCount = 164; // 4
inline constexpr std::size_t kOffRecoveriesTotal = 168; // 4
inline constexpr std::size_t kOffGapsTotal = 172;       // 4
inline constexpr std::size_t kOffDfailTotal = 176;      // 4 (v0.3.3, A010 F60)
inline constexpr std::size_t kOffExtReserved = 180;     // 4 (v0.3.3, must be 0)
inline constexpr std::size_t kOffDagg = 184;            // 32
// ---- trailer ----
inline constexpr std::size_t kOffEventTag = kBodySize;                     // 144
inline constexpr std::size_t kOffEventCrc = kOffEventTag + kTagSize;       // 176
inline constexpr std::size_t kOffSignedTag = kSignedBodySize;              // 216
inline constexpr std::size_t kOffSig = kOffSignedTag + kTagSize;           // 248
inline constexpr std::size_t kOffSignedCrc = kOffSig + kSigSize;           // 312
static_assert(kOffSignedCrc + kCrcSize == kSignedRecordSize && kOffEventCrc + kCrcSize == kEventRecordSize);

struct FieldSpec { std::string_view name; std::size_t offset; std::size_t size; };
// In layout order; tag/sig/crc32 at their SIGNED-record offsets. CTest layout_vs_spec
// compares this table with the output of tests/spec/layout_v0_3_3.py.
inline constexpr std::array<FieldSpec, 35> kFieldTable{{
    {"magic", kOffMagic, 4}, {"version", kOffVersion, 1}, {"rec_type", kOffRecType, 1},
    {"event_code", kOffEventCode, 2}, {"rec_len", kOffRecLen, 4}, {"reason", kOffReason, 2},
    {"actor_class", kOffActorClass, 1}, {"dmethod", kOffDmethod, 1}, {"seq", kOffSeq, 8},
    {"epoch", kOffEpoch, 4}, {"len_bucket", kOffLenBucket, 1}, {"sflags", kOffSflags, 1},
    {"dmode", kOffDmode, 1}, {"reserved1", kOffReserved1, 1}, {"ts_ms", kOffTsMs, 8},
    {"mono_ms", kOffMonoMs, 8}, {"subj_first", kOffSubjFirst, 8}, {"subj_last", kOffSubjLast, 8},
    {"count", kOffCount, 4}, {"actor_uid", kOffActorUid, 4}, {"bytes", kOffBytes, 8},
    {"digest", kOffDigest, 32}, {"prev_link", kOffPrevLink, 32},
    {"nv_export", kOffNvExport, 8}, {"tpm_clock_ms", kOffTpmClockMs, 8},
    {"tpm_reset_count", kOffTpmResetCount, 4}, {"tpm_restart_count", kOffTpmRestartCount, 4},
    {"recoveries_total", kOffRecoveriesTotal, 4}, {"gaps_total", kOffGapsTotal, 4},
    {"dfail_total", kOffDfailTotal, 4}, {"ext_reserved", kOffExtReserved, 4},
    {"d_agg", kOffDagg, 32}, {"tag", kOffSignedTag, kTagSize}, {"sig", kOffSig, kSigSize},
    {"crc32", kOffSignedCrc, kCrcSize},
}};

// ---- fixed header values ----
inline constexpr std::array<std::uint8_t, 4> kMagic{{'C', 'T', 'A', 'C'}};
inline constexpr std::uint8_t kVersion = 1;

enum class RecType : std::uint8_t { genesis = 1, event = 2, checkpoint = 3, epoch_start = 4 };
inline constexpr std::uint8_t kRtGenesis = 1, kRtEvent = 2, kRtCheckpoint = 3, kRtEpochStart = 4;
inline constexpr std::uint8_t kRecTypeMin = 1, kRecTypeMax = 4;
inline constexpr bool is_signed_type(std::uint8_t rt) { return rt == kRtGenesis || rt == kRtCheckpoint || rt == kRtEpochStart; }
inline constexpr std::size_t record_size_for(std::uint8_t rt) { return rt == kRtEvent ? kEventRecordSize : kSignedRecordSize; }
inline constexpr std::size_t body_size_for(std::uint8_t rt) { return rt == kRtEvent ? kBodySize : kSignedBodySize; }
inline constexpr std::size_t tag_offset_for(std::uint8_t rt) { return rt == kRtEvent ? kOffEventTag : kOffSignedTag; }

// dmethod (offset 15) and dmode (offset 30), C4
inline constexpr std::uint8_t kDmKeyed = 1, kDmAbsent = 2, kDmNotApplicable = 3, kDmKeyedFailed = 4;
inline constexpr std::uint8_t kDmethodMin = 1, kDmethodMax = 4;
// dmethod 5 is RESERVED for the C8 option O1 (batched HMAC): FAIL in v1, like 0 and 6-255.
inline constexpr std::uint8_t kDmethodReservedBatched = 5;
inline constexpr std::uint8_t kDmodeKeyed = 1, kDmodeAbsent = 2;

// actor_class (offset 14)
inline constexpr std::uint8_t kActorNone = 0, kActorSystem = 1, kActorReceiver = 2, kActorStaff = 3,
                              kActorSource = 4, kActorClassMax = 4;

// len_bucket (Q9): 0 unused, else 1 + ceil(log2(len)). v0.3.3 (A009 F47): 1..65 valid,
// covering every u64 (bucket(2^64-1) == 65); 66+ is e_field.
inline constexpr std::uint8_t kLenBucketMax = 65;

// sflags (offset 29). Signed records: bit0 TPMS_CLOCK_INFO.safe (writer-reported);
// bit1 SUCCESSOR lineage (F49): equals the GENESIS value in every signed record;
// bit2 DIGEST_FAILED (F52/F60): set iff dfail_total > 0, never clears; bits 3-7 = 0.
// EVENT: 0. bit1 / bit2 -> exit 6.
inline constexpr std::uint8_t kSflagClockSafe = 0x01;
inline constexpr std::uint8_t kSflagSuccessor = 0x02;
inline constexpr std::uint8_t kSflagDigestFailed = 0x04;
inline constexpr std::uint8_t kSflagsSignedAllowed = kSflagClockSafe | kSflagSuccessor | kSflagDigestFailed;
inline constexpr std::uint8_t kSflagsEventAllowed = 0x00;

// Saturating u32 counters (gaps_total, dfail_total, 71 count)
inline constexpr std::uint32_t kCounterSaturated = UINT32_MAX;

// C3 transfer rules
inline constexpr std::uint64_t kXferGranularityMs = 1000;   // G_xfer
inline constexpr std::uint32_t kExactTotalMinFrames = 32;

inline constexpr std::uint64_t kSeqInvalid = UINT64_MAX;     // 2^64-1 is FAIL
inline constexpr std::uint32_t kEpochInvalid = UINT32_MAX;   // 2^32-1 is FAIL

// 5.1 / 6.2 file limits
inline constexpr std::uint64_t kSegmentRollBytes = 64ull * 1024 * 1024;
inline constexpr std::uint64_t kMaxChainFileBytes = kSegmentRollBytes + kSignedRecordSize;

// ---- domain-separation labels (ASCII, no terminator; prefix-free, checked in tests) ----
inline constexpr std::string_view kDsLink = "ct01.audit_chain.v1.link";
inline constexpr std::string_view kDsTag = "ct01.audit_chain.v1.tag";
inline constexpr std::string_view kDsCkpt = "ct01.audit_chain.v1.ckpt";
inline constexpr std::string_view kDsEpochKey = "ct01.audit_chain.v1.epoch_key";
inline constexpr std::string_view kDsDgstGrp = "ct01.audit_chain.v1.dgst.grp";
inline constexpr std::string_view kDsDgstAct = "ct01.audit_chain.v1.dgst.act";
inline constexpr std::string_view kDsDgstTorn = "ct01.audit_chain.v1.dgst.torn";
inline constexpr std::string_view kDsDgstPred = "ct01.audit_chain.v1.dgst.pred";
inline constexpr std::string_view kDsDgstAgg = "ct01.audit_chain.v1.dgst.agg";
inline constexpr std::string_view kDsCertify = "ct01.audit_chain.v1.certify";
inline constexpr std::string_view kDsDgstTpmrec = "ct01.audit_chain.v1.dgst.tpmrec";
inline constexpr std::string_view kDsGenesis = "ct01.audit_chain.v1.genesis";
inline constexpr std::string_view kDsAllowlist = "ct01.audit_chain.v1.allowlist";
inline constexpr std::string_view kDsGapCtr = "ct01.audit_chain.v1.gapctr";
inline constexpr std::array<std::string_view, 14> kAllLabels{{kDsLink, kDsTag, kDsCkpt, kDsEpochKey, kDsDgstGrp,
    kDsDgstAct, kDsDgstTorn, kDsDgstPred, kDsDgstAgg, kDsCertify, kDsDgstTpmrec, kDsGenesis, kDsAllowlist, kDsGapCtr}};
inline constexpr std::size_t kSignedPreimageSize = 56;   // DS_CKPT (24) || h (32)
static_assert(kDsCkpt.size() + kHashSize == kSignedPreimageSize, "56 B signed pre-image");

// ---- decoded record ----
using Hash = std::array<std::uint8_t, kHashSize>;
using ChainId = std::array<std::uint8_t, kChainIdSize>;
using Sig = std::array<std::uint8_t, kSigSize>;

struct RecordFields {
    std::uint8_t version = kVersion;
    std::uint8_t rec_type = 0;
    std::uint16_t event_code = 0;
    std::uint32_t rec_len = 0;
    std::uint16_t reason = 0;
    std::uint8_t actor_class = 0;
    std::uint8_t dmethod = 0;
    std::uint64_t seq = 0;
    std::uint32_t epoch = 0;
    std::uint8_t len_bucket = 0;
    std::uint8_t sflags = 0;
    std::uint8_t dmode = 0;
    std::uint8_t reserved1 = 0;
    std::uint64_t ts_ms = 0;
    std::uint64_t mono_ms = 0;
    std::uint64_t subj_first = 0;
    std::uint64_t subj_last = 0;
    std::uint32_t count = 0;
    std::uint32_t actor_uid = 0;
    std::uint64_t bytes = 0;
    Hash digest{};
    Hash prev_link{};
    // signed extension (rec_type != event)
    std::uint64_t nv_export = 0;
    std::uint64_t tpm_clock_ms = 0;
    std::uint32_t tpm_reset_count = 0;
    std::uint32_t tpm_restart_count = 0;
    std::uint32_t recoveries_total = 0;
    std::uint32_t gaps_total = 0;
    std::uint32_t dfail_total = 0;
    std::uint32_t ext_reserved = 0;
    Hash d_agg{};
    // trailer
    Hash tag{};
    Sig sig{};
    std::uint32_t crc32 = 0;
};

// ---- per-code rules (4.2 columns + 6.2 per-code verifier table) ----
// Where the 4.2 table is silent the CONSERVATIVE reading is used (field must be 0);
// every such choice is listed in README.md "Open questions".
enum class Subj : std::uint8_t {
    zero,       // subj_first == subj_last == 0
    range,      // subj_first <= subj_last
    single,     // subj_first == subj_last
    strict,     // subj_first <  subj_last (64)
    free_,      // any (48-52 "expected..got or 0"; 68 "committed .. coverage")
    ckpt,       // CHECKPOINT: prev signed seq .. this seq (chain rule, e_ckpt_range)
};
enum class Count : std::uint8_t { zero, one, at_least_one, holder_id, free_ };
enum class Digest : std::uint8_t {
    signed_special,  // GENESIS / CHECKPOINT / EPOCH_START: key ids, checked by the verifier
    bearing,         // 16, 72: dmethod per epoch dmode (1 or 4 under keyed, 2 under absent)
    optional,        // 35-38: dmethod 3 (no operator token) or per epoch dmode
    zero,            // dmethod 3, digest all-zero
    na_free,         // dmethod 3, digest per 4.2 (64 torn, 65 pred, 71 tpmrec)
};
enum class Bytes : std::uint8_t { zero, xfer_exact, free_, groups_nonzero };
enum class Actor : std::uint8_t { none_only, staff_uid_allowed, staff_required };

struct EventSpec {
    std::uint16_t code;
    std::uint8_t rec_type;
    std::string_view name;
    Subj subj;
    Count count;
    Actor actor;
    bool len_bucket;     // the len_bucket column allows a bucket
    Bytes bytes;
    Digest digest;
    bool ts_coarse;      // 22/23: ts_ms and mono_ms multiples of kXferGranularityMs
};

// Event code numbers, per-code reason values and FAIL-reason numbers: include/ct01/codes.hpp
// (generated from DESIGN v0.3.4 Appendix A, frozen). This header only adds the per-code FIELD rules.
namespace code = ::ct01::audit::codes::code;
namespace reason = ::ct01::audit::codes::reason;
inline constexpr std::array<std::uint16_t, ::ct01::audit::codes::kCodeTables.size()> kDesignCodes = [] {
    std::array<std::uint16_t, ::ct01::audit::codes::kCodeTables.size()> a{};
    for (std::size_t i = 0; i < a.size(); ++i) a[i] = ::ct01::audit::codes::kCodeTables[i].code;
    return a;
}();

using A = Actor;
inline constexpr std::array<EventSpec, 36> kEventSpecs{{
    // code, rec_type, name, subj, count, actor, len_bucket, bytes, digest, ts_coarse (reasons: codes.hpp)
    {code::genesis, kRtGenesis, "genesis", Subj::single, Count::free_, A::staff_uid_allowed, false, Bytes::free_, Digest::signed_special, false},
    {code::checkpoint, kRtCheckpoint, "checkpoint", Subj::ckpt, Count::free_, A::none_only, false, Bytes::zero, Digest::signed_special, false},
    {code::epoch_start, kRtEpochStart, "epoch_start", Subj::zero, Count::zero, A::none_only, false, Bytes::zero, Digest::signed_special, false},
    {16, kRtEvent, "recv_group_delivered", Subj::range, Count::free_, A::none_only, true, Bytes::zero, Digest::bearing, false},
    {17, kRtEvent, "recv_void", Subj::single, Count::one, A::none_only, false, Bytes::zero, Digest::zero, false},
    {18, kRtEvent, "recv_export_intent", Subj::range, Count::free_, A::staff_uid_allowed, false, Bytes::zero, Digest::zero, false},
    {19, kRtEvent, "recv_export_outcome", Subj::range, Count::free_, A::staff_uid_allowed, false, Bytes::zero, Digest::zero, false},
    {20, kRtEvent, "recv_log_fault", Subj::range, Count::zero, A::none_only, true, Bytes::zero, Digest::zero, false},
    {21, kRtEvent, "recv_log_torn_tail", Subj::range, Count::zero, A::none_only, true, Bytes::zero, Digest::zero, false},
    {22, kRtEvent, "recv_transfer_start", Subj::range, Count::free_, A::none_only, false, Bytes::zero, Digest::zero, true},
    {23, kRtEvent, "recv_transfer_end", Subj::range, Count::free_, A::none_only, true, Bytes::xfer_exact, Digest::zero, true},
    {32, kRtEvent, "buffer_open", Subj::zero, Count::zero, A::none_only, false, Bytes::zero, Digest::zero, false},
    {33, kRtEvent, "ack_purge_intent", Subj::range, Count::free_, A::none_only, false, Bytes::zero, Digest::zero, false},
    {34, kRtEvent, "ack_purge_outcome", Subj::range, Count::free_, A::none_only, false, Bytes::zero, Digest::zero, false},
    {35, kRtEvent, "record_erase_intent", Subj::single, Count::one, A::staff_uid_allowed, false, Bytes::zero, Digest::optional, false},
    {36, kRtEvent, "record_erase_outcome", Subj::single, Count::one, A::staff_uid_allowed, false, Bytes::zero, Digest::optional, false},
    {37, kRtEvent, "factory_reset_intent", Subj::zero, Count::zero, A::staff_uid_allowed, false, Bytes::zero, Digest::optional, false},
    {38, kRtEvent, "factory_reset_outcome", Subj::zero, Count::zero, A::staff_uid_allowed, false, Bytes::zero, Digest::optional, false},
    {39, kRtEvent, "buffer_fault", Subj::zero, Count::zero, A::none_only, false, Bytes::zero, Digest::zero, false},
    {48, kRtEvent, "contingency_pass_through", Subj::free_, Count::free_, A::none_only, false, Bytes::zero, Digest::zero, false},
    {49, kRtEvent, "nack_gap_replay", Subj::free_, Count::free_, A::none_only, false, Bytes::zero, Digest::zero, false},
    {50, kRtEvent, "void_acked", Subj::free_, Count::free_, A::none_only, false, Bytes::zero, Digest::zero, false},
    {51, kRtEvent, "kek_unavailable", Subj::free_, Count::free_, A::none_only, false, Bytes::zero, Digest::zero, false},
    {52, kRtEvent, "mem_lock_failed", Subj::free_, Count::free_, A::none_only, false, Bytes::zero, Digest::zero, false},
    {64, kRtEvent, "chain_torn_tail_recovered", Subj::strict, Count::free_, A::none_only, false, Bytes::free_, Digest::na_free, false},
    {65, kRtEvent, "chain_predecessor", Subj::single, Count::zero, A::none_only, false, Bytes::zero, Digest::na_free, false},
    {66, kRtEvent, "chain_gap", Subj::range, Count::at_least_one, A::none_only, false, Bytes::zero, Digest::zero, false},
    {67, kRtEvent, "holder_ack", Subj::single, Count::holder_id, A::none_only, false, Bytes::zero, Digest::zero, false},
    {68, kRtEvent, "recv_coverage", Subj::free_, Count::zero, A::none_only, false, Bytes::zero, Digest::zero, false},
    {69, kRtEvent, "fault_ack", Subj::single, Count::zero, A::staff_uid_allowed, false, Bytes::zero, Digest::zero, false},
    {70, kRtEvent, "config_mismatch", Subj::zero, Count::zero, A::none_only, false, Bytes::zero, Digest::zero, false},
    {71, kRtEvent, "tpm_recovered", Subj::range, Count::free_, A::none_only, false, Bytes::zero, Digest::na_free, false},
    {72, kRtEvent, "recv_groups_compacted", Subj::range, Count::free_, A::none_only, true, Bytes::groups_nonzero, Digest::bearing, false},
    {73, kRtEvent, "commissioning_verified", Subj::zero, Count::free_, A::staff_required, false, Bytes::zero, Digest::zero, false},
    {74, kRtEvent, "lockdown", Subj::zero, Count::free_, A::none_only, false, Bytes::zero, Digest::zero, false},
    {75, kRtEvent, "audit_space_level", Subj::zero, Count::zero, A::none_only, false, Bytes::zero, Digest::zero, false},
}};

inline constexpr const EventSpec* find_event_spec(std::uint16_t c) {
    for (const auto& s : kEventSpecs)
        if (s.code == c) return &s;
    return nullptr;
}

// GENESIS digest = chain_id || first 16 B of S_0's key id (4.1).
inline constexpr std::size_t kGenesisKeyIdPrefix = kHashSize - kChainIdSize;

// Q9 bucket: 0 for len 0 (unused), else 1 + ceil(log2(len)).
inline constexpr std::uint8_t len_bucket_of(std::uint64_t len) {
    if (len == 0) return 0;
    std::uint64_t v = len - 1;
    std::uint8_t bits = 0;
    while (v) { ++bits; v >>= 1; }
    return static_cast<std::uint8_t>(1 + bits);
}
static_assert(len_bucket_of(UINT64_MAX) == kLenBucketMax);

}  // namespace ct01::audit::layout
