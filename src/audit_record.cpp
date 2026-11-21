#include "ct01/audit_record.hpp"

#include "ct01/audit_crypto.hpp"

#include <cstring>
#include <stdexcept>

namespace ct01::audit {

using namespace layout;
namespace c = crypto;

namespace {
template <typename T> void put(std::uint8_t* p, std::size_t off, T v) {
    for (std::size_t i = 0; i < sizeof(T); ++i) p[off + i] = static_cast<std::uint8_t>(static_cast<std::uint64_t>(v) >> (8 * i));
}
template <typename T> T get(const std::uint8_t* p, std::size_t off) {
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < sizeof(T); ++i) v |= static_cast<std::uint64_t>(p[off + i]) << (8 * i);
    return static_cast<T>(v);
}
template <std::size_t N> void put_arr(std::uint8_t* p, std::size_t off, const std::array<std::uint8_t, N>& a) {
    std::memcpy(p + off, a.data(), N);
}
template <std::size_t N> void get_arr(const std::uint8_t* p, std::size_t off, std::array<std::uint8_t, N>& a) {
    std::memcpy(a.data(), p + off, N);
}
}  // namespace

bool is_zero(const Hash& h) {
    std::uint8_t acc = 0;
    for (auto b : h) acc |= b;
    return acc == 0;
}

HeaderParse parse_header(const std::uint8_t* p, std::size_t n) {
    HeaderParse h;
    if (n < kHeaderParseSize) { h.reason = Reason::e_short; return h; }
    if (std::memcmp(p + kOffMagic, kMagic.data(), kMagic.size()) != 0) { h.reason = Reason::e_magic; return h; }
    if (p[kOffVersion] != kVersion) { h.reason = Reason::e_version; return h; }
    const std::uint8_t rt = p[kOffRecType];
    if (rt < kRecTypeMin || rt > kRecTypeMax) { h.reason = Reason::e_rec_type; return h; }
    const std::uint32_t rl = get<std::uint32_t>(p, kOffRecLen);
    if (rl != record_size_for(rt)) { h.reason = Reason::e_rec_len; return h; }
    h.rec_len = rl;
    return h;
}

RecordBytes encode_record(const RecordFields& f) {
    const std::size_t n = record_size_for(f.rec_type);
    RecordBytes b(n, 0);
    std::uint8_t* p = b.data();
    put_arr(p, kOffMagic, kMagic);
    p[kOffVersion] = f.version;
    p[kOffRecType] = f.rec_type;
    put(p, kOffEventCode, f.event_code);
    put(p, kOffRecLen, f.rec_len);
    put(p, kOffReason, f.reason);
    p[kOffActorClass] = f.actor_class;
    p[kOffDmethod] = f.dmethod;
    put(p, kOffSeq, f.seq);
    put(p, kOffEpoch, f.epoch);
    p[kOffLenBucket] = f.len_bucket;
    p[kOffSflags] = f.sflags;
    p[kOffDmode] = f.dmode;
    p[kOffReserved1] = f.reserved1;
    put(p, kOffTsMs, f.ts_ms);
    put(p, kOffMonoMs, f.mono_ms);
    put(p, kOffSubjFirst, f.subj_first);
    put(p, kOffSubjLast, f.subj_last);
    put(p, kOffCount, f.count);
    put(p, kOffActorUid, f.actor_uid);
    put(p, kOffBytes, f.bytes);
    put_arr(p, kOffDigest, f.digest);
    put_arr(p, kOffPrevLink, f.prev_link);
    if (is_signed_type(f.rec_type)) {
        put(p, kOffNvExport, f.nv_export);
        put(p, kOffTpmClockMs, f.tpm_clock_ms);
        put(p, kOffTpmResetCount, f.tpm_reset_count);
        put(p, kOffTpmRestartCount, f.tpm_restart_count);
        put(p, kOffRecoveriesTotal, f.recoveries_total);
        put(p, kOffGapsTotal, f.gaps_total);
        put(p, kOffDfailTotal, f.dfail_total);
        put(p, kOffExtReserved, f.ext_reserved);
        put_arr(p, kOffDagg, f.d_agg);
        put_arr(p, kOffSignedTag, f.tag);
        put_arr(p, kOffSig, f.sig);
        put(p, kOffSignedCrc, f.crc32);
    } else {
        put_arr(p, kOffEventTag, f.tag);
        put(p, kOffEventCrc, f.crc32);
    }
    return b;
}

RecordFields decode_record(const std::uint8_t* p, std::size_t n) {
    RecordFields f;
    f.rec_type = p[kOffRecType];
    if (n < record_size_for(f.rec_type)) throw std::logic_error("decode_record: short buffer");
    f.version = p[kOffVersion];
    f.event_code = get<std::uint16_t>(p, kOffEventCode);
    f.rec_len = get<std::uint32_t>(p, kOffRecLen);
    f.reason = get<std::uint16_t>(p, kOffReason);
    f.actor_class = p[kOffActorClass];
    f.dmethod = p[kOffDmethod];
    f.seq = get<std::uint64_t>(p, kOffSeq);
    f.epoch = get<std::uint32_t>(p, kOffEpoch);
    f.len_bucket = p[kOffLenBucket];
    f.sflags = p[kOffSflags];
    f.dmode = p[kOffDmode];
    f.reserved1 = p[kOffReserved1];
    f.ts_ms = get<std::uint64_t>(p, kOffTsMs);
    f.mono_ms = get<std::uint64_t>(p, kOffMonoMs);
    f.subj_first = get<std::uint64_t>(p, kOffSubjFirst);
    f.subj_last = get<std::uint64_t>(p, kOffSubjLast);
    f.count = get<std::uint32_t>(p, kOffCount);
    f.actor_uid = get<std::uint32_t>(p, kOffActorUid);
    f.bytes = get<std::uint64_t>(p, kOffBytes);
    get_arr(p, kOffDigest, f.digest);
    get_arr(p, kOffPrevLink, f.prev_link);
    if (is_signed_type(f.rec_type)) {
        f.nv_export = get<std::uint64_t>(p, kOffNvExport);
        f.tpm_clock_ms = get<std::uint64_t>(p, kOffTpmClockMs);
        f.tpm_reset_count = get<std::uint32_t>(p, kOffTpmResetCount);
        f.tpm_restart_count = get<std::uint32_t>(p, kOffTpmRestartCount);
        f.recoveries_total = get<std::uint32_t>(p, kOffRecoveriesTotal);
        f.gaps_total = get<std::uint32_t>(p, kOffGapsTotal);
        f.dfail_total = get<std::uint32_t>(p, kOffDfailTotal);
        f.ext_reserved = get<std::uint32_t>(p, kOffExtReserved);
        get_arr(p, kOffDagg, f.d_agg);
        get_arr(p, kOffSignedTag, f.tag);
        get_arr(p, kOffSig, f.sig);
        f.crc32 = get<std::uint32_t>(p, kOffSignedCrc);
    } else {
        get_arr(p, kOffEventTag, f.tag);
        f.crc32 = get<std::uint32_t>(p, kOffEventCrc);
    }
    return f;
}

std::uint32_t compute_crc(const std::uint8_t* rec, std::size_t rec_len) { return c::crc32_ieee(rec, rec_len - kCrcSize); }
bool crc_ok(const std::uint8_t* rec, std::size_t rec_len) {
    return compute_crc(rec, rec_len) == get<std::uint32_t>(rec, rec_len - kCrcSize);
}

Hash compute_link(const ChainId& chain_id, const std::uint8_t* rec, std::size_t rec_len) {
    const std::uint8_t rt = rec[kOffRecType];
    const std::size_t body = body_size_for(rt);
    if (rec_len < body) throw std::logic_error("compute_link: short record");
    if (rt == kRtEvent) {
        static const std::uint8_t zero[kHashSize] = {};
        return c::sha256({c::span(kDsLink), c::span(chain_id), c::Span{rec, kOffDigest}, c::Span{zero, kHashSize},
                          c::Span{rec + kOffDigest + kHashSize, body - kOffDigest - kHashSize}});
    }
    return c::sha256({c::span(kDsLink), c::span(chain_id), c::Span{rec, body}});
}

Hash compute_tag(const Hash& epoch_key, const Hash& link, const Hash& digest) {
    return c::hmac_sha256(c::span(epoch_key), {c::span(kDsTag), c::span(link), c::span(digest)});
}

Hash signed_message_digest(const Hash& link) { return c::sha256({c::span(kDsCkpt), c::span(link)}); }

Hash derive_epoch_key(const ChainId& chain_id, const Hash& tag_root, std::uint32_t epoch) {
    std::vector<std::uint8_t> info(kDsEpochKey.begin(), kDsEpochKey.end());
    for (int i = 0; i < 4; ++i) info.push_back(static_cast<std::uint8_t>(epoch >> (8 * i)));
    const auto k = c::hkdf_sha256(c::span(chain_id), c::span(tag_root), c::span(info), kHashSize);
    Hash out{};
    std::memcpy(out.data(), k.data(), kHashSize);
    return out;
}

Hash compute_dagg(const std::vector<Hash>& digests) {
    std::vector<std::uint8_t> cat;
    cat.reserve(digests.size() * kHashSize);
    for (const auto& d : digests) cat.insert(cat.end(), d.begin(), d.end());
    return c::sha256({c::span(kDsDgstAgg), c::span(cat)});
}

Hash compute_tpmrec(const Hash& last_keyed_link) { return c::sha256({c::span(kDsDgstTpmrec), c::span(last_keyed_link)}); }

Hash software_key_id(const std::array<std::uint8_t, 65>& sec1) { return c::sha256({c::span(sec1)}); }

Reason check_record_fields(const RecordFields& f) {
    const EventSpec* s = find_event_spec(f.event_code);
    if (!s || s->rec_type != f.rec_type) return Reason::e_event_code;
    // Reason values: DESIGN v0.3.4 Appendix A.2 (codes.hpp); any value not listed = e_reason.
    if (!codes::reason_allowed(f.event_code, f.reason)) return Reason::e_reason;
    // actor
    if (f.actor_class > kActorClassMax) return Reason::e_actor;
    if (s->actor == Actor::staff_required && f.actor_class != kActorStaff) return Reason::e_actor;
    if (f.actor_uid != 0) {
        if (f.actor_class == kActorNone || f.actor_class == kActorSource) return Reason::e_field;
        if (s->actor == Actor::none_only) return Reason::e_field;
    }
    // dmethod / dmode / digest (context-free part; dmode-of-epoch agreement is a chain rule)
    if (f.dmethod < kDmethodMin || f.dmethod > kDmethodMax) return Reason::e_dmethod;
    const bool signed_rec = is_signed_type(f.rec_type);
    const bool dz = is_zero(f.digest);
    if (signed_rec) {
        if (f.dmode != kDmodeKeyed && f.dmode != kDmodeAbsent) return Reason::e_dmode;
        if (f.dmethod != kDmNotApplicable) return Reason::e_dmethod;
    } else {
        if (f.dmode != 0) return Reason::e_dmode;
        switch (s->digest) {
            case Digest::zero: if (f.dmethod != kDmNotApplicable || !dz) return Reason::e_dmethod; break;
            case Digest::na_free: if (f.dmethod != kDmNotApplicable) return Reason::e_dmethod; break;
            case Digest::bearing: if (f.dmethod == kDmNotApplicable) return Reason::e_dmethod; [[fallthrough]];
            case Digest::optional:
                if (f.dmethod == kDmKeyed && dz) return Reason::e_dmethod;
                if ((f.dmethod == kDmAbsent || f.dmethod == kDmKeyedFailed || f.dmethod == kDmNotApplicable) && !dz)
                    return Reason::e_dmethod;
                break;
            case Digest::signed_special: return Reason::e_event_code;
        }
    }
    if (f.seq == kSeqInvalid) return Reason::e_seq;
    if (f.epoch == kEpochInvalid) return Reason::e_epoch;
    // len_bucket
    if (f.len_bucket > kLenBucketMax) return Reason::e_field;
    if (f.len_bucket != 0 && !s->len_bucket) return Reason::e_field;
    // flags / reserved
    if (signed_rec) {
        if (f.sflags & static_cast<std::uint8_t>(~kSflagsSignedAllowed)) return Reason::e_reserved;
        if (f.ext_reserved != 0) return Reason::e_reserved;
    } else if (f.sflags & static_cast<std::uint8_t>(~kSflagsEventAllowed)) {
        return Reason::e_reserved;
    }
    if (f.reserved1 != 0) return Reason::e_reserved;
    // timestamps (C3)
    if (s->ts_coarse && (f.ts_ms % kXferGranularityMs != 0 || f.mono_ms % kXferGranularityMs != 0)) return Reason::e_ts_gran;
    // subject range
    switch (s->subj) {
        case Subj::zero: if (f.subj_first != 0 || f.subj_last != 0) return Reason::e_field; break;
        case Subj::range: if (f.subj_last < f.subj_first) return Reason::e_field; break;
        case Subj::single: if (f.subj_last != f.subj_first) return Reason::e_field; break;
        case Subj::strict: if (f.subj_last <= f.subj_first) return Reason::e_field; break;
        case Subj::free_: break;
        case Subj::ckpt:
            if (f.subj_last < f.subj_first || f.subj_last - f.subj_first > UINT32_MAX ||
                f.count != f.subj_last - f.subj_first) return Reason::e_ckpt_range;
            break;
    }
    switch (s->count) {
        case Count::zero: if (f.count != 0) return Reason::e_field; break;
        case Count::one: if (f.count != 1) return Reason::e_field; break;
        case Count::at_least_one: if (f.count < 1) return Reason::e_field; break;
        case Count::holder_id: if (f.count != 1 && f.count != 2) return Reason::e_field; break;
        case Count::free_: break;
    }
    switch (s->bytes) {
        case Bytes::zero: if (f.bytes != 0) return Reason::e_field; break;
        case Bytes::xfer_exact: if (f.bytes != 0 && f.count < kExactTotalMinFrames) return Reason::e_field; break;
        case Bytes::free_: break;
        case Bytes::groups_nonzero: if (f.bytes == 0) return Reason::e_field; break;
    }
    // signed-record specifics
    if (f.rec_type == kRtGenesis) {
        const bool succ = (f.sflags & kSflagSuccessor) != 0;
        // sflags bit1: 0 for reason 1; 1 for reasons 3-6; either for reason 2 (provisioned or not) (A009 F49).
        if (f.reason == reason::genesis::provisioning && succ) return Reason::e_genesis;
        if (f.reason >= reason::genesis::fail_successor && !succ) return Reason::e_genesis;
        // A011 F66 / v0.3.4 4.2 row 1: reasons 1, 2, 4, 5, 6 FORCE last good seq (subj), FAIL reason (count)
        // and v_chain (bytes) to 0; only reason 3 carries them, and its FAIL reason must be 1..40.
        if (f.reason == reason::genesis::fail_successor) {
            if (f.count < 1 || f.count > kFailReasonMax) return Reason::e_genesis;
        } else if (f.subj_first != 0 || f.subj_last != 0 || f.count != 0 || f.bytes != 0) {
            return Reason::e_genesis;
        }
        if (f.dfail_total != 0 || (f.sflags & kSflagDigestFailed)) return Reason::e_flag;
    }
    if (f.rec_type == kRtEpochStart && !is_zero(f.d_agg)) return Reason::e_field;   // v0.3.4 4.1 d_agg row: zero [e_field]
    if (signed_rec && ((f.sflags & kSflagDigestFailed) != 0) != (f.dfail_total > 0)) return Reason::e_flag;
    return Reason::none;
}

Sealed seal_record(RecordFields f, const ChainId& chain_id, const Hash* epoch_key, const c::TestOnlyP256Signer* signer) {
    f.rec_len = static_cast<std::uint32_t>(record_size_for(f.rec_type));
    f.tag = Hash{};
    f.sig = Sig{};
    f.crc32 = 0;
    RecordBytes b = encode_record(f);
    Sealed out;
    out.link = compute_link(chain_id, b.data(), b.size());
    if (epoch_key) {
        const Hash t = compute_tag(*epoch_key, out.link, f.digest);
        std::memcpy(b.data() + tag_offset_for(f.rec_type), t.data(), kTagSize);
    }
    if (is_signed_type(f.rec_type) && signer) {
        const auto sig = signer->sign_prehashed(signed_message_digest(out.link));
        if (!sig) throw std::runtime_error("seal_record: signing failed");
        std::memcpy(b.data() + kOffSig, sig->data(), kSigSize);
    }
    const std::uint32_t crc = compute_crc(b.data(), b.size());
    put(b.data(), b.size() - kCrcSize, crc);
    out.bytes = std::move(b);
    return out;
}

}  // namespace ct01::audit
