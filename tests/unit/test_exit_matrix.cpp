// Exit-code matrix (DESIGN v0.3.4 6.2, A008 F46, 8.11): every code 0-6, 7-9 never emitted, and the
// precedence 1 > 2 > 6 > 5 > 4 > 3 > 0 via the ONE shared function exit_code_for().
#include "doctest.h"
#include "test_support.hpp"

using namespace ct01::audit;
using namespace ct01::audit::test;
namespace L = ct01::audit::layout;

namespace {
Builder clean(int groups = 6) {
    Builder b;
    b.genesis();
    for (int i = 0; i < groups; ++i) { b.group(); if (i % 3 == 2) b.checkpoint(); }
    if (b.recs.back().rec_type != L::kRtCheckpoint) b.checkpoint();
    return b;
}
std::vector<std::uint8_t> torn(std::vector<std::uint8_t> v, std::size_t n) {
    std::vector<std::uint8_t> stub(v.end() - 180, v.end() - 180 + static_cast<long>(n));
    v.insert(v.end(), stub.begin(), stub.end());
    return v;
}
}  // namespace

TEST_CASE("precedence function: exhaustive over all qualifier combinations; 7-9 never emitted") {
    for (unsigned m = 0; m < (1u << 9); ++m) {
        Outcome o;
        o.io_or_usage_error = m & 1; o.fail = m & 2; o.recovered = m & 4; o.gap = m & 8; o.successor = m & 16;
        o.digest_failed = m & 32; o.tail_unverified = m & 64; o.unanchored = m & 128; o.torn_tail = m & 256;
        const int rc = exit_code_for(o);
        CHECK(rc >= 0);
        CHECK(rc <= 6);
        int want = 0;
        if (o.io_or_usage_error) want = 1;
        else if (o.fail) want = 2;
        else if (o.recovered || o.gap || o.successor || o.digest_failed) want = 6;
        else if (o.tail_unverified) want = 5;
        else if (o.unanchored) want = 4;
        else if (o.torn_tail) want = 3;
        CHECK(rc == want);
    }
    for (int rc = -1; rc <= 10; ++rc) CHECK(is_qualified_accept(rc) == (rc >= 3 && rc <= 6));
    CHECK_FALSE(is_accept(1));
    CHECK_FALSE(is_accept(2));
    CHECK_FALSE(is_accept(7));
    CHECK(is_accept(0));
    CHECK(result_name(7) == "reserved");
}

TEST_CASE("exit 0: keyed, anchored, clean (V0)") {
    auto b = clean();
    auto r = verify(b, b.build(), true, true);
    CHECK(r.exit == 0);
    CHECK(r.qualifiers().empty());
    CHECK(r.records_after_anchor == std::optional<std::uint64_t>(0));
}

TEST_CASE("exit 4: no anchor; exit 0 public when the last record is a checkpoint and anchored") {
    auto b = clean();
    CHECK(verify(b, b.build(), true, false).exit == 4);
    CHECK(verify(b, b.build(), false, false).exit == 4);
    CHECK(verify(b, b.build(), false, true).exit == 0);
}

TEST_CASE("exit 3: torn stub in the newest file (< 180 B, and header parses but < rec_len)") {
    auto b = clean();
    auto r1 = verify(b, torn(b.build(), 100), true, true);
    CHECK(r1.exit == 3);
    CHECK(r1.torn_bytes == 100);
    auto r2 = verify(b, torn(b.build(), 179), true, true);
    CHECK(r2.exit == 3);
    // signed header (rec_len 316) with 200 B present: torn
    auto v = b.build();
    std::vector<std::uint8_t> stub(v.end() - 316, v.end() - 116);
    v.insert(v.end(), stub.begin(), stub.end());
    CHECK(verify(b, v, true, true).exit == 3);
    // >= 180 B that does not parse: FAIL, not torn
    auto w = b.build();
    std::vector<std::uint8_t> junk(200, 0x5a);
    w.insert(w.end(), junk.begin(), junk.end());
    auto r3 = verify(b, w, true, true);
    CHECK(r3.exit == 2);
    CHECK(r3.reason == Reason::e_magic);
}

TEST_CASE("exit 5: public mode, records after the last signature; keyed mode covers them by tags") {
    auto b = clean();
    b.group();
    b.group();
    auto r = verify(b, b.build(), false, true);
    CHECK(r.exit == 5);
    CHECK(r.tail_unverified_from == std::optional<std::uint64_t>(b.recs.size() - 2));
    CHECK(verify(b, b.build(), true, true).exit == 0);
}

TEST_CASE("exit 6: recovered / gap / successor / digest_failed each, permanent in the newest signed record") {
    SUBCASE("recoveries_total > 0") {
        auto b = clean();
        b.event(codes::code::chain_torn_tail_recovered, 0, 3, 5, 0);
        b.recoveries = 1;
        b.checkpoint();
        auto r = verify(b, b.build(), true, true);
        CHECK(r.exit == 6);
        CHECK(r.qualifiers() == std::vector<std::string>{"recovered"});
    }
    SUBCASE("gaps_total > 0") {
        auto b = clean();
        b.event(codes::code::chain_gap, codes::reason::chain_gap::unrecordable, 500, 510, 3);
        b.gaps = 3;
        b.checkpoint();
        auto r = verify(b, b.build(), true, true);
        CHECK(r.exit == 6);
        CHECK(r.qualifiers() == std::vector<std::string>{"gap"});
    }
    SUBCASE("successor lineage (GENESIS reason 3, bit1)") {
        Builder b;
        b.genesis(3);
        b.recs[0].subj_first = b.recs[0].subj_last = 1234;
        b.group();
        b.checkpoint();
        auto r = verify(b, b.build(), true, true);
        CHECK(r.exit == 6);
        CHECK(r.qualifiers() == std::vector<std::string>{"successor"});
    }
    SUBCASE("digest_failed: dmethod 4 run + 71, bit2 + dfail_total") {
        auto b = clean();
        b.group(32, L::kDmKeyedFailed);
        b.group(32, L::kDmKeyedFailed);
        // 71: range == run, count == 2, digest == tpmrec(h of last dmethod-1 record)
        std::vector<Hash> links;
        b.build(&links);   // links up to now; last dmethod-1 group is at index size-4 (before ckpt)
        std::size_t last_dm1 = 0;
        for (std::size_t i = 0; i < b.recs.size(); ++i) if (b.recs[i].dmethod == L::kDmKeyed) last_dm1 = i;
        auto& t = b.event(codes::code::tpm_recovered, 0, b.recs.size() - 2, b.recs.size() - 1, 2);
        t.digest = compute_tpmrec(links[last_dm1]);
        b.checkpoint();
        auto r = verify(b, b.build(), true, true);
        CHECK(r.exit == 6);
        CHECK(r.qualifiers() == std::vector<std::string>{"digest_failed"});
        CHECK(r.dfail_total == 2);
        CHECK(r.failed_records == 2);
    }
    SUBCASE("all-dmethod-4 chain -> 6 (8.11)") {
        Builder b;
        b.genesis();
        b.group(32, L::kDmKeyedFailed);
        b.checkpoint();
        CHECK(verify(b, b.build(), true, true).exit == 6);
    }
}

TEST_CASE("precedence on real chains: 6 > 5 > 4 > 3, FAIL > 6") {
    auto b = clean();
    b.event(codes::code::chain_gap, codes::reason::chain_gap::unrecordable, 500, 510, 3);
    b.gaps = 3;
    b.checkpoint();
    b.group();   // public tail
    auto bytes = torn(b.build(), 50);
    auto r = verify(b, bytes, false, false);   // gap + tail + unanchored + torn
    CHECK(r.exit == 6);
    CHECK(r.qualifiers() == std::vector<std::string>{"gap", "tail_unverified", "unanchored", "torn_tail"});
    auto c = clean();
    c.group();
    auto r5 = verify(c, torn(c.build(), 50), false, false);   // tail + unanchored + torn
    CHECK(r5.exit == 5);
    auto r4 = verify(c, torn(c.build(), 50), true, false);    // unanchored + torn
    CHECK(r4.exit == 4);
    // FAIL beats 6
    b.after_seal = [](std::size_t i, RecordBytes& rb) { if (i == 2) rb[100] ^= 1; };
    auto rf = verify(b, b.build(), true, true);
    CHECK(rf.exit == 2);
    CHECK(rf.qualifiers().empty());
}

TEST_CASE("exit 1: io/usage (no --pubkeys, no files, oversize file)") {
    VerifyOptions o;
    CHECK(verify_chain({{"a.ac", {}}}, o).exit == 1);
    auto keys = keys_of(Builder().pubkeys());
    o.pubkeys = &keys;
    CHECK(verify_chain({}, o).exit == 1);
    ChainFile big{"a.ac", std::vector<std::uint8_t>(L::kMaxChainFileBytes + 1, 0)};
    CHECK(verify_chain({big}, o).exit == 1);
}

TEST_CASE("device self-check path and CLI library path give identical reports (one shared verifier)") {
    for (int variant = 0; variant < 3; ++variant) {
        auto b = clean();
        if (variant == 1) b.group();
        if (variant == 2) b.after_seal = [](std::size_t i, RecordBytes& rb) { if (i == 3) rb[60] ^= 4; };
        auto bytes = b.build();
        auto keys = keys_of(b.pubkeys());
        std::map<std::uint32_t, Hash> k;
        for (auto& [e, rt] : b.roots) k[e] = derive_epoch_key(b.chain_id, rt, e);
        auto dev = device_self_check({{"seg_00000000.ac", bytes}}, keys, k, std::nullopt);
        auto cli = verify(b, bytes, true, false);
        CHECK(dev.exit == cli.exit);
        CHECK(dev.reason == cli.reason);
        CHECK(dev.first_bad_seq == cli.first_bad_seq);
        CHECK(dev.qualifiers() == cli.qualifiers());
    }
}
