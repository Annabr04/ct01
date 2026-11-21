// Test-only chain builder: seals ARBITRARY records (including ones the M1 writer refuses: 64, 66, 71,
// dmethod 4, successor GENESIS) so the verifier's rules and every exit code can be exercised.
// TEST-ONLY software keys; synthetic data only.
#pragma once

#include "ct01/audit_crypto.hpp"
#include "ct01/audit_inputs.hpp"
#include "ct01/audit_record.hpp"
#include "ct01/audit_verify.hpp"
#include "ct01/audit_writer.hpp"

#include <cstring>
#include <functional>
#include <stdexcept>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace ct01::audit::test {

namespace L = layout;
namespace C = crypto;

inline C::TestOnlyP256Signer test_signer(std::uint8_t tag) {
    Hash d{};
    d[29] = 0x7e;
    d[31] = tag;
    return *C::TestOnlyP256Signer::from_scalar(d);
}
inline Hash filled(std::uint8_t b) { Hash h; h.fill(b); return h; }

struct Builder {
    ChainId chain_id{};
    std::map<std::uint32_t, C::TestOnlyP256Signer> signers;
    std::map<std::uint32_t, Hash> roots;   // R^t_e
    std::vector<RecordFields> recs;
    std::uint32_t epoch = 0;
    std::uint8_t dmode = L::kDmodeKeyed;
    std::uint64_t fwd = 0, ts = 1'700'000'000'000ull;
    bool bit1 = false;
    std::uint32_t recoveries = 0, gaps = 0;

    Builder() {
        for (std::size_t i = 0; i < chain_id.size(); ++i) chain_id[i] = static_cast<std::uint8_t>(0xc0 + i);
        signers.emplace(0, test_signer(1));
        roots[0] = filled(0x31);
    }
    std::uint64_t next_seq() const { return recs.size(); }
    Hash key_id(std::uint32_t e) const { return software_key_id(signers.at(e).public_sec1()); }

    RecordFields& genesis(std::uint16_t reason = 1) {
        RecordFields f;
        f.rec_type = L::kRtGenesis;
        f.event_code = codes::code::genesis;
        f.reason = reason;
        f.dmethod = L::kDmNotApplicable;
        f.dmode = dmode;
        bit1 = reason >= 3;
        if (reason == 3) f.count = static_cast<std::uint32_t>(Reason::e_tag);
        const Hash kid = key_id(0);
        std::memcpy(f.digest.data(), chain_id.data(), 16);
        std::memcpy(f.digest.data() + 16, kid.data(), 16);
        return push(f);
    }
    RecordFields& push(RecordFields f) {
        f.ts_ms = f.mono_ms = (ts += 1000);
        recs.push_back(f);
        return recs.back();
    }
    RecordFields& group(std::uint32_t frames = 32, std::uint8_t dm = 0) {
        RecordFields f;
        f.rec_type = L::kRtEvent;
        f.event_code = codes::code::recv_group_delivered;
        f.actor_class = L::kActorReceiver;
        f.subj_first = fwd + 1;
        f.subj_last = fwd + frames;
        fwd += frames;
        f.count = frames;
        f.len_bucket = 7;
        f.dmethod = dm ? dm : (dmode == L::kDmodeKeyed ? L::kDmKeyed : L::kDmAbsent);
        if (f.dmethod == L::kDmKeyed) f.digest = filled(static_cast<std::uint8_t>(0x10 + recs.size()));
        return push(f);
    }
    RecordFields& event(std::uint16_t c, std::uint16_t reason, std::uint64_t sf = 0, std::uint64_t sl = 0, std::uint32_t count = 0) {
        RecordFields f;
        f.rec_type = L::kRtEvent;
        f.event_code = c;
        f.reason = reason;
        f.dmethod = L::kDmNotApplicable;
        f.subj_first = sf;
        f.subj_last = sl;
        f.count = count;
        return push(f);
    }
    RecordFields& checkpoint(std::uint16_t reason = 1) {
        RecordFields f;
        f.rec_type = L::kRtCheckpoint;
        f.event_code = codes::code::checkpoint;
        f.reason = reason;
        f.dmethod = L::kDmNotApplicable;
        f.dmode = dmode;
        f.digest = key_id(epoch);
        f.recoveries_total = recoveries;
        f.gaps_total = gaps;
        return push(f);
    }
    RecordFields& epoch_start(std::uint8_t new_dmode = 0) {
        const std::uint32_t ne = epoch + 1;
        if (!signers.count(ne)) signers.emplace(ne, test_signer(static_cast<std::uint8_t>(1 + ne)));
        if (!roots.count(ne)) roots[ne] = filled(static_cast<std::uint8_t>(0x31 + ne));
        RecordFields f;
        f.rec_type = L::kRtEpochStart;
        f.event_code = codes::code::epoch_start;
        f.reason = 1;
        f.dmethod = L::kDmNotApplicable;
        if (new_dmode) dmode = new_dmode;
        f.dmode = dmode;
        f.digest = key_id(ne);
        f.epoch = ne;
        epoch = ne;
        f.recoveries_total = recoveries;
        f.gaps_total = gaps;
        return push(f);
    }

    // Seal everything: seq, epoch, prev_link, rec_len, counters (dfail running count, bit1/bit2),
    // checkpoint range and d_agg (F71) are filled unless `raw` is set on that index.
    std::function<void(std::size_t, RecordFields&)> before_seal;   // last-minute field tamper
    std::function<void(std::size_t, RecordBytes&)> after_seal;     // byte tamper (no reseal)
    std::vector<std::uint8_t> build(std::vector<Hash>* links = nullptr) const {
        std::vector<std::uint8_t> out;
        Hash prev{};
        std::uint32_t cur_epoch = 0, dfail = 0;
        std::uint64_t last_signed = 0;
        std::vector<Hash> range;
        for (std::size_t i = 0; i < recs.size(); ++i) {
            RecordFields f = recs[i];
            f.seq = i;
            if (f.rec_type == L::kRtEpochStart) cur_epoch = f.epoch;
            f.epoch = cur_epoch;
            f.prev_link = prev;
            f.rec_len = static_cast<std::uint32_t>(L::record_size_for(f.rec_type));
            if (L::is_signed_type(f.rec_type)) {
                for (std::size_t j = static_cast<std::size_t>(last_signed) + 1; j < i && i > 0; ++j)
                    if (recs[j].rec_type == L::kRtEvent && recs[j].dmethod == L::kDmKeyedFailed) ++dfail;
                f.dfail_total = dfail;
                f.sflags = static_cast<std::uint8_t>((f.sflags & L::kSflagClockSafe) | (bit1 ? L::kSflagSuccessor : 0) |
                                                     (dfail ? L::kSflagDigestFailed : 0));
                if (f.rec_type == L::kRtCheckpoint) {
                    f.subj_first = last_signed;
                    f.subj_last = i;
                    f.count = static_cast<std::uint32_t>(i - last_signed);
                    f.d_agg = compute_dagg(range);
                }
            }
            if (before_seal) before_seal(i, f);
            const std::uint32_t signer_epoch = f.rec_type == L::kRtEpochStart ? f.epoch - 1 : f.epoch;
            const C::TestOnlyP256Signer* s = L::is_signed_type(f.rec_type) ? &signers.at(signer_epoch) : nullptr;
            std::optional<Hash> k;
            auto r = roots.find(f.epoch);
            if (r != roots.end()) k = derive_epoch_key(chain_id, r->second, f.epoch);
            Sealed sealed = seal_record(f, chain_id, k ? &*k : nullptr, s);
            if (after_seal) after_seal(i, sealed.bytes);
            out.insert(out.end(), sealed.bytes.begin(), sealed.bytes.end());
            if (links) links->push_back(sealed.link);
            prev = sealed.link;
            if (L::is_signed_type(f.rec_type)) { last_signed = i; range.clear(); }
            else range.push_back(f.digest);
        }
        return out;
    }

    std::string pubkeys(bool pinned = true) const {
        std::string s = "ct01-audit-pubkeys v1\n";
        // epoch e: [first signed seq of e, seq of EPOCH_START(e+1)] ; last epoch open
        std::uint64_t first = 0;
        std::uint32_t e = 0;
        for (std::size_t i = 0; i < recs.size(); ++i) {
            if (recs[i].rec_type == L::kRtEpochStart) {
                s += line(e, first, std::to_string(i), pinned);
                first = i + 1;
                ++e;
            }
        }
        s += line(e, first, "open", pinned);
        return s;
    }
    std::string line(std::uint32_t e, std::uint64_t first, const std::string& last, bool pinned) const {
        return "epoch=" + std::to_string(e) + " first=" + std::to_string(first) + " last=" + last + " key_id=" +
               (pinned ? C::to_hex(key_id(e)) : std::string("unpinned")) + " pub=" + C::to_hex(signers.at(e).public_sec1()) + "\n";
    }
};

struct Run {
    Report rep;
    int exit() const { return rep.exit; }
    Reason reason() const { return rep.reason; }
};

inline PubKeyList keys_of(const std::string& text) {
    std::string err;
    auto k = parse_pubkeys(text, err);
    if (!k) throw std::runtime_error("pubkeys: " + err);
    return *k;
}

// Verify one-file chain. keyed: pass R^t for all epochs. anchor: head (or given seq).
inline Report verify(const Builder& b, const std::vector<std::uint8_t>& bytes, bool keyed, bool anchored,
                     const std::optional<std::string>& pubkeys_override = std::nullopt, std::vector<ChainFile> files = {}) {
    static thread_local PubKeyList keys;
    keys = keys_of(pubkeys_override ? *pubkeys_override : b.pubkeys());
    VerifyOptions o;
    o.pubkeys = &keys;
    if (keyed) o.tag_roots = b.roots;
    if (anchored) {
        // anchor at the newest complete record: rebuild links
        std::vector<Hash> links;
        b.build(&links);
        Anchor a;
        a.chain_id = b.chain_id;
        a.seq = links.size() - 1;
        a.link = links.back();
        o.anchor = a;
    }
    if (files.empty()) files.push_back({"seg_00000000.ac", bytes});
    return verify_chain(files, o);
}

inline std::string warnings_of(const Report& r) {
    std::string s;
    for (const auto& w : r.warnings) s += w.code + ",";
    return s;
}

}  // namespace ct01::audit::test
