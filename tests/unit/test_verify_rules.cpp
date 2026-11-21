// Verifier rules not covered by the independent reference verifier (multi-epoch, pinned ranges, key ids, files,
// pruned starts) plus the v0.3.4 rules F66 / F70 / F71 and A012 F76 / F77.
#include "doctest.h"
#include "test_support.hpp"

using namespace ct01::audit;
using namespace ct01::audit::test;
namespace L = ct01::audit::layout;
namespace R = ct01::audit::codes::reason;
namespace K = ct01::audit::codes::code;

namespace {
Builder base() {
    Builder b;
    b.genesis();
    b.group();
    b.group();
    b.checkpoint();
    return b;
}
Report run(const Builder& b, bool keyed = true) { return verify(b, b.build(), keyed, false); }
bool has_warning(const Report& r, const std::string& w) {
    for (const auto& x : r.warnings) if (x.code == w) return true;
    return false;
}
}  // namespace

TEST_CASE("F70 forward-seq: 16/17/72 advance E; jump is a warning only; resets on 68, 22 reseed, GENESIS") {
    SUBCASE("VOID consumes a seq: no warning") {
        auto b = base();
        b.fwd += 1;
        b.event(K::recv_void, 0, b.fwd, b.fwd, 1);
        b.group();
        b.checkpoint();
        auto r = run(b);
        CHECK(r.exit == 4);
        CHECK_FALSE(has_warning(r, "fwd_seq_jump"));
    }
    SUBCASE("jump: warning fwd_seq_jump, exit unchanged") {
        auto b = base();
        b.fwd += 100;
        b.group();
        b.checkpoint();
        auto r = run(b);
        CHECK(r.exit == 4);
        CHECK(has_warning(r, "fwd_seq_jump"));
    }
    SUBCASE("re-use after 68 rollback: no warning") {
        auto b = base();
        b.event(K::recv_coverage, R::recv_coverage::group_rolled_back, b.fwd - 31, b.fwd, 0);
        b.fwd -= 32;
        b.group();
        b.checkpoint();
        auto r = run(b);
        CHECK(r.exit == 4);
        CHECK_FALSE(has_warning(r, "fwd_seq_jump"));
    }
    SUBCASE("22 reason reseed resets; 22 reason normal does not") {
        for (int reseed = 0; reseed < 2; ++reseed) {
            auto b = base();
            auto& t = b.event(K::recv_transfer_start, reseed ? R::recv_transfer_start::reseed : R::recv_transfer_start::normal, 5000, 5000, 0);
            (void)t;
            b.fwd = 4999;
            b.group();
            b.checkpoint();
            b.before_seal = [](std::size_t, RecordFields& f) {
                if (f.event_code == K::recv_transfer_start) f.ts_ms = f.mono_ms = f.ts_ms - f.ts_ms % 1000;
            };
            auto r = run(b);
            CHECK(r.exit == 4);
            CHECK(has_warning(r, "fwd_seq_jump") == (reseed == 0));
        }
    }
    SUBCASE("level-4 66 above E -> e_gap_range; covering from E -> accepted (gap -> 6)") {
        for (int undercover = 0; undercover < 2; ++undercover) {
            auto b = base();
            b.event(K::audit_space_level, R::audit_space_level::level2);
            b.event(K::audit_space_level, R::audit_space_level::level3);
            b.event(K::audit_space_level, R::audit_space_level::level4);
            b.gaps = 1;
            b.checkpoint(R::checkpoint::level4_entry);
            const std::uint64_t first = b.fwd + 1 + (undercover ? 32 : 0);
            b.event(K::chain_gap, R::chain_gap::audit_space, first, b.fwd + 288, 9);
            b.fwd += 288;
            b.gaps = 9;
            b.event(K::audit_space_level, R::audit_space_level::level3);
            b.checkpoint(R::checkpoint::level4_exit);
            b.group();
            b.checkpoint();
            auto r = run(b);
            if (undercover) {
                CHECK(r.exit == 2);
                CHECK(r.reason == Reason::e_gap_range);
                CHECK(static_cast<int>(r.reason) == 36);
            } else {
                CHECK(r.exit == 6);
                CHECK_FALSE(has_warning(r, "fwd_seq_jump"));
            }
        }
    }
    SUBCASE("E unknown at the first record: a 66 cannot FAIL before any 16") {
        Builder b;
        b.genesis();
        b.event(K::audit_space_level, 2);
        b.event(K::audit_space_level, 3);
        b.event(K::audit_space_level, 4);
        b.event(K::chain_gap, R::chain_gap::audit_space, 900, 950, 2);
        b.gaps = 2;
        b.checkpoint();
        CHECK(run(b).exit == 6);
    }
}

TEST_CASE("F71 d_agg: every EVENT digest (zeros included), both dmodes; wrong -> e_dagg (40)") {
    SUBCASE("dmode 2 with non-zero d_agg (aggregate of zeros) passes") {
        Builder b;
        b.dmode = L::kDmodeAbsent;
        b.genesis();
        b.group();
        b.group();
        b.checkpoint();
        auto r = run(b);
        CHECK(r.exit == 4);
        CHECK_FALSE(is_zero(compute_dagg({Hash{}, Hash{}})));
    }
    SUBCASE("dmode 2 checkpoint with a zero d_agg (old v0.3.3 rule) FAILs e_dagg") {
        Builder b;
        b.dmode = L::kDmodeAbsent;
        b.genesis();
        b.group();
        b.checkpoint();
        b.before_seal = [](std::size_t, RecordFields& f) { if (f.rec_type == L::kRtCheckpoint) f.d_agg = Hash{}; };
        auto r = run(b);
        CHECK(r.reason == Reason::e_dagg);
        CHECK(static_cast<int>(r.reason) == 40);
    }
    SUBCASE("aggregate must include zero digests of non-digest records (dm1-only aggregate FAILs)") {
        auto b = base();
        b.event(K::buffer_open, 0);
        b.group();
        b.checkpoint();
        b.before_seal = [&](std::size_t i, RecordFields& f) {
            if (i == b.recs.size() - 1) f.d_agg = compute_dagg({b.recs[i - 1].digest});   // drops the 32 zero digest
        };
        CHECK(run(b).reason == Reason::e_dagg);
    }
    SUBCASE("EPOCH_START d_agg must be zero (e_field)") {
        auto b = base();
        b.epoch_start();
        b.checkpoint();
        b.before_seal = [](std::size_t, RecordFields& f) { if (f.rec_type == L::kRtEpochStart) f.d_agg = filled(1); };
        CHECK(run(b).reason == Reason::e_field);
    }
}

TEST_CASE("F66 GENESIS: reasons 1,2,4,5,6 force zeros; reason 3 carries FAIL reason 1..40") {
    struct C { std::uint16_t reason; std::uint64_t last_good; std::uint32_t fail; std::uint64_t vchain; Reason want; };
    const C cases[] = {
        {1, 0, 0, 0, Reason::none}, {2, 0, 0, 0, Reason::none}, {4, 0, 0, 0, Reason::none},
        {4, 7, 0, 0, Reason::e_genesis}, {5, 0, 0, 3, Reason::e_genesis}, {6, 0, 2, 0, Reason::e_genesis},
        {2, 0, 0, 9, Reason::e_genesis}, {3, 5, 17, 2, Reason::none}, {3, 0, 17, 0, Reason::none},
        {3, 5, 0, 2, Reason::e_genesis}, {3, 5, 41, 2, Reason::e_genesis}, {7, 0, 0, 0, Reason::e_reason},
        {0, 0, 0, 0, Reason::e_reason},
    };
    for (const auto& c : cases) {
        Builder b;
        b.genesis(c.reason);
        b.recs[0].subj_first = b.recs[0].subj_last = c.last_good;
        b.recs[0].count = c.fail;
        b.recs[0].bytes = c.vchain;
        b.group();
        b.checkpoint();
        auto r = run(b);
        CAPTURE(c.reason);
        CAPTURE(c.last_good);
        CAPTURE(c.fail);
        CHECK(r.reason == c.want);
    }
    // bit1 rules: reason 1 must be 0; reasons 3-6 must be 1; reason 2 either
    Builder b;
    b.genesis(1);
    b.bit1 = true;
    b.group();
    b.checkpoint();
    CHECK(run(b).reason == Reason::e_genesis);
}

TEST_CASE("F66 per-code reason tables (Appendix A.2): unlisted value = e_reason (6)") {
    auto b = base();
    b.event(K::recv_export_outcome, 0, 1, 2, 0);   // 19 allows only 1 ok / 2 failed
    b.checkpoint();
    auto r = run(b);
    CHECK(r.reason == Reason::e_reason);
    CHECK(static_cast<int>(r.reason) == 6);
    auto c = base();
    c.recs.back().reason = 12;   // CHECKPOINT reasons 1..11
    CHECK(run(c).reason == Reason::e_reason);
    for (const auto& t : codes::kCodeTables) {   // every listed value passes the reason check
        for (std::size_t i = 0; i < t.reason_count; ++i) CHECK(codes::reason_allowed(t.code, t.reasons[i].value));
        CHECK_FALSE(codes::reason_allowed(t.code, 999));
    }
    CHECK(kReasonNames.size() == 41);
    CHECK(kReasonNames[40] == "e_dagg");
    CHECK(static_cast<int>(Reason::e_sig) == 18);
    CHECK(reason_name(Reason::e_epoch_handover) == "e_epoch_handover");
}

TEST_CASE("69 fault_ack: target must be FAULT-raising; reason gap -> must be a 66 (e_ack_ref)") {
    for (int variant = 0; variant < 4; ++variant) {
        auto b = base();
        const std::uint64_t grp = 1;                    // a 16 (not fault-raising)
        const std::uint64_t fault = b.next_seq();
        b.event(K::recv_log_fault, R::recv_log_fault::io);
        const std::uint64_t target = variant == 1 ? grp : fault;
        auto& a = b.event(K::fault_ack, variant == 2 ? R::fault_ack::gap : R::fault_ack::fault, target, target, 0);
        a.actor_class = L::kActorStaff;
        a.actor_uid = 77;
        if (variant == 3) a.subj_first = a.subj_last = 4000;   // not an earlier record
        b.checkpoint();
        auto r = run(b);
        CAPTURE(variant);
        CHECK(r.reason == (variant == 0 ? Reason::none : Reason::e_ack_ref));
    }
}

TEST_CASE("71 tpm_recovered: range == dmethod-4 run, count/reason, digest == tpmrec(last dm1 link)") {
    for (int variant = 0; variant < 4; ++variant) {
        auto b = base();
        b.group(32, L::kDmKeyedFailed);
        b.group(32, L::kDmKeyedFailed);
        std::vector<Hash> links;
        b.build(&links);
        auto& t = b.event(K::tpm_recovered, 0, b.recs.size() - 2, b.recs.size() - 1, 2);
        t.digest = compute_tpmrec(links[2]);
        if (variant == 1) t.count = 3;
        if (variant == 2) t.reason = R::tpm_recovered::saturated;   // reason saturated without saturated count
        if (variant == 3) t.digest = compute_tpmrec(links[1]);
        b.checkpoint();
        auto r = run(b);
        CAPTURE(variant);
        CHECK(r.reason == (variant == 0 ? Reason::none : Reason::e_tpmrec));
        if (variant == 0) CHECK(r.exit == 6);
    }
}

TEST_CASE("75 ladder: +-1 steps, first is level 2, leaving 4 needs a level-4 66; open at end -> gap_open") {
    auto lad = [](std::vector<std::uint16_t> levels, bool gap_before_exit) {
        auto b = base();
        for (auto l : levels) {
            if (l == 3 && gap_before_exit && !b.recs.empty() && b.recs.back().event_code == K::audit_space_level &&
                b.recs.back().reason == 4) {
                b.event(K::chain_gap, R::chain_gap::audit_space, b.fwd + 1, b.fwd + 10, 1);
                b.fwd += 10;
                b.gaps = 1;
            }
            b.event(K::audit_space_level, l);
        }
        b.checkpoint();
        return run(b);
    };
    CHECK(lad({2, 1}, false).reason == Reason::none);
    CHECK(lad({1}, false).reason == Reason::e_level);
    CHECK(lad({3}, false).reason == Reason::e_level);
    CHECK(lad({2, 4}, false).reason == Reason::e_level);
    CHECK(lad({2, 3, 4, 3}, false).reason == Reason::e_level);
    CHECK(lad({2, 3, 4, 3}, true).reason == Reason::none);
    auto open = lad({2, 3, 4}, false);
    CHECK(open.reason == Reason::none);
    CHECK(has_warning(open, "gap_open"));
    CHECK(lad({2, 5, 1}, false).reason == Reason::none);   // reserve_tampered is not a level change
    // a level-4 66 without a 75 level 4 first -> e_level (F67 entry missing)
    auto b = base();
    b.event(K::chain_gap, R::chain_gap::audit_space, b.fwd + 1, b.fwd + 64, 2);
    b.gaps = 2;
    b.checkpoint();
    CHECK(run(b).reason == Reason::e_level);
}

TEST_CASE("74 lockdown failed -> warning lockdown_failed, restored -> none; 73 -> commissioning info") {
    auto b = base();
    b.event(K::lockdown, R::lockdown::failed);
    b.event(K::lockdown, R::lockdown::restored);
    auto& c = b.event(K::commissioning_verified, 0, 0, 0, 0x01500020);
    c.actor_class = L::kActorStaff;
    c.actor_uid = 5;
    b.checkpoint();
    auto r = run(b);
    CHECK(r.exit == 4);
    CHECK(has_warning(r, "lockdown_failed"));
    CHECK(has_warning(r, "commissioning"));
    int n = 0;
    for (auto& w : r.warnings) n += w.code == "lockdown_failed";
    CHECK(n == 1);
}

TEST_CASE("multi-epoch handover with pinned ranges; A012 F76 / F77") {
    SUBCASE("valid 0 -> 1 -> 2 handover, keyed and public") {
        auto b = base();
        b.epoch_start();
        b.checkpoint();
        b.group();
        b.checkpoint();
        b.epoch_start(L::kDmodeAbsent);
        b.checkpoint();
        b.group();
        b.checkpoint();
        auto r = run(b);
        CHECK(r.exit == 4);
        CHECK(r.epochs.size() == 3);
        CHECK(r.epochs[2].dmode == L::kDmodeAbsent);
        CHECK(run(b, false).exit == 4);
    }
    SUBCASE("F76: EPOCH_START not IMMEDIATELY after a CHECKPOINT -> e_epoch_handover (27)") {
        auto b = base();
        b.group();
        b.epoch_start();
        b.checkpoint();
        auto r = run(b);
        CHECK(r.reason == Reason::e_epoch_handover);
        CHECK(static_cast<int>(r.reason) == 27);
    }
    SUBCASE("F77: unknown / missing checkpoint pubkey -> e_sig (18)") {
        auto b = base();
        b.epoch_start();
        b.checkpoint();
        std::string only0 = "ct01-audit-pubkeys v1\n" + b.line(0, 0, "open", true);
        auto r = verify(b, b.build(), true, false, only0);   // epoch 1 key absent
        CHECK(r.reason == Reason::e_sig);
        CHECK(static_cast<int>(r.reason) == 18);
        // a different (unknown) key for epoch 0
        Builder other;
        other.signers.erase(0);
        other.signers.emplace(0, test_signer(99));
        auto r2 = verify(base(), base().build(), true, false, "ct01-audit-pubkeys v1\n" + other.line(0, 0, "open", false));
        CHECK(r2.reason == Reason::e_sig);
    }
    SUBCASE("signature outside the pinned seq range -> e_epoch") {
        auto b = base();
        b.epoch_start();
        b.checkpoint();
        // pin epoch 0 to [0, 2] (EPOCH_START at seq 4 is then outside)
        std::string p = "ct01-audit-pubkeys v1\n" + b.line(0, 0, "2", true) + b.line(1, 4, "open", true);
        CHECK(verify(b, b.build(), true, false, p).reason == Reason::e_epoch);
    }
    SUBCASE("EPOCH_START digest must be the pinned key id of S_{e+1}") {
        auto b = base();
        b.epoch_start();
        b.checkpoint();
        b.before_seal = [](std::size_t, RecordFields& f) { if (f.rec_type == L::kRtEpochStart) f.digest = filled(7); };
        CHECK(run(b).reason == Reason::e_epoch_handover);
    }
    SUBCASE("epoch skip -> e_epoch") {
        auto b = base();
        b.epoch_start();
        b.checkpoint();
        b.before_seal = [](std::size_t, RecordFields& f) { if (f.rec_type == L::kRtEpochStart) f.epoch = 2; };
        CHECK(run(b, false).reason == Reason::e_epoch);
    }
}

TEST_CASE("key-id claims: GENESIS prefix and CHECKPOINT signer id vs pinned --pubkeys") {
    auto b = base();
    b.before_seal = [](std::size_t, RecordFields& f) { if (f.rec_type == L::kRtCheckpoint) f.digest = filled(3); };
    CHECK(run(b).reason == Reason::e_sig);
    CHECK(verify(b, b.build(), true, false, b.pubkeys(false)).reason == Reason::none);   // unpinned: warning only
    auto g = base();
    g.before_seal = [](std::size_t, RecordFields& f) { if (f.rec_type == L::kRtGenesis) f.digest[20] ^= 1; };
    CHECK(run(g).reason == Reason::e_genesis);
}

TEST_CASE("counters and sticky flags") {
    SUBCASE("dfail_total must equal the running count of dmethod 4 -> e_counter") {
        auto b = base();
        b.group(32, L::kDmKeyedFailed);
        b.checkpoint();
        b.before_seal = [](std::size_t i, RecordFields& f) { if (i == 5) { f.dfail_total = 2; } };
        CHECK(run(b).reason == Reason::e_counter);
    }
    SUBCASE("bit2 iff dfail_total > 0 -> e_flag") {
        auto b = base();
        b.before_seal = [](std::size_t i, RecordFields& f) { if (i == 3) f.sflags |= L::kSflagDigestFailed; };
        CHECK(run(b).reason == Reason::e_flag);
    }
    SUBCASE("bit1 constant per chain -> e_flag") {
        auto b = base();
        b.before_seal = [](std::size_t i, RecordFields& f) { if (i == 3) f.sflags |= L::kSflagSuccessor; };
        CHECK(run(b).reason == Reason::e_flag);
    }
    SUBCASE("counters never decrease -> e_counter") {
        auto b = base();
        b.recs.back().gaps_total = 4;
        b.group();
        b.checkpoint();
        CHECK(run(b).reason == Reason::e_counter);
    }
}

TEST_CASE("files: order, chain_id in name, torn record in a non-last file, pruned start") {
    auto b = base();
    b.group();
    b.checkpoint();
    auto all = b.build();
    const std::size_t cut = 316 + 2 * 180 + 316;   // GENESIS, 2 groups, CHECKPOINT
    std::vector<std::uint8_t> a(all.begin(), all.begin() + cut), c(all.begin() + cut, all.end());
    const std::string hex = C::to_hex(b.chain_id);
    auto keys = keys_of(b.pubkeys());
    VerifyOptions o;
    o.pubkeys = &keys;
    CHECK(verify_chain({{"chain_" + hex + "_00000000.ac", a}, {"chain_" + hex + "_00000001.ac", c}}, o).exit == 4);
    CHECK(verify_chain({{"chain_" + hex + "_00000001.ac", a}, {"chain_" + hex + "_00000000.ac", c}}, o).reason == Reason::e_file_order);
    std::string other(32, 'a');
    CHECK(verify_chain({{"chain_" + other + "_00000000.ac", a}}, o).reason == Reason::e_unexpected_chain_id);
    std::vector<std::uint8_t> a_torn(a.begin(), a.end() - 10);
    CHECK(verify_chain({{"x0.ac", a_torn}, {"x1.ac", c}}, o).reason == Reason::e_short);
    // pruned start: second file only, anchored at its head -> accepted with warning
    std::vector<Hash> links;
    b.build(&links);
    Anchor an{links.size() - 1, links.back(), b.chain_id};
    o.anchor = an;
    auto r = verify_chain({{"x1.ac", c}}, o);
    CHECK(r.exit == 0);
    CHECK(r.pruned_start);
    CHECK(has_warning(r, "pruned_start"));
    o.anchor.reset();
    CHECK(verify_chain({{"x1.ac", c}}, o).reason == Reason::e_no_genesis);
}

TEST_CASE("anchor: mismatch, behind, wrong chain_id") {
    auto b = base();
    auto bytes = b.build();
    std::vector<Hash> links;
    b.build(&links);
    auto keys = keys_of(b.pubkeys());
    VerifyOptions o;
    o.pubkeys = &keys;
    o.anchor = Anchor{2, links[2], b.chain_id};
    auto r = verify_chain({{"a.ac", bytes}}, o);
    CHECK(r.exit == 0);
    CHECK(r.records_after_anchor == std::optional<std::uint64_t>(1));
    o.anchor = Anchor{2, links[1], b.chain_id};
    CHECK(verify_chain({{"a.ac", bytes}}, o).reason == Reason::e_anchor_mismatch);
    o.anchor = Anchor{9, links[1], b.chain_id};
    CHECK(verify_chain({{"a.ac", bytes}}, o).reason == Reason::e_behind_anchor);
    ChainId wrong{};
    o.anchor = Anchor{2, links[2], wrong};
    CHECK(verify_chain({{"a.ac", bytes}}, o).reason == Reason::e_unexpected_chain_id);
}

TEST_CASE("basic tamper: link, tag, sig, crc, seq") {
    auto b = base();
    auto v = b.build();
    auto flip = [&](std::size_t off, bool keyed) {
        auto w = v;
        w[off] ^= 1;
        return verify(b, w, keyed, false).reason;
    };
    CHECK(flip(316 + 100, true) == Reason::e_crc);                 // body flip without CRC fix
    Builder t = b;
    t.after_seal = [](std::size_t i, RecordBytes& rb) {
        if (i == 1) { rb[150] ^= 1; const auto c = compute_crc(rb.data(), rb.size());
            for (int k = 0; k < 4; ++k) rb[176 + k] = static_cast<std::uint8_t>(c >> (8 * k)); }
    };
    CHECK(verify(t, t.build(), true, false).reason == Reason::e_tag);
    CHECK(verify(t, t.build(), false, false).exit == 4);           // public mode cannot see an EVENT tag flip
    Builder s = b;
    s.after_seal = [](std::size_t i, RecordBytes& rb) {
        if (i == 3) { rb[260] ^= 1; const auto c = compute_crc(rb.data(), rb.size());
            for (int k = 0; k < 4; ++k) rb[312 + k] = static_cast<std::uint8_t>(c >> (8 * k)); }
    };
    CHECK(verify(s, s.build(), false, false).reason == Reason::e_sig);
    Builder l = b;
    l.before_seal = [](std::size_t i, RecordFields& f) { if (i == 2) f.prev_link[0] ^= 1; };
    CHECK(verify(l, l.build(), false, false).reason == Reason::e_link);
    // drop a record -> seq gap
    std::vector<std::uint8_t> drop(v.begin(), v.begin() + 316);
    drop.insert(drop.end(), v.begin() + 316 + 180, v.end());
    CHECK(verify(b, drop, false, false).reason == Reason::e_seq);
}
