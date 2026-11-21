// Context-free field rules (4.1 / 4.2) and the input parsers (--pubkeys, --anchor, --epoch-key).
#include "doctest.h"
#include "test_support.hpp"

using namespace ct01::audit;
using namespace ct01::audit::test;
namespace L = ct01::audit::layout;
namespace K = ct01::audit::codes::code;

namespace {
RecordFields grp() {
    RecordFields f;
    f.rec_type = L::kRtEvent;
    f.event_code = K::recv_group_delivered;
    f.rec_len = 180;
    f.actor_class = L::kActorReceiver;
    f.dmethod = L::kDmKeyed;
    f.digest = filled(1);
    f.subj_first = 1;
    f.subj_last = 32;
    f.count = 32;
    f.len_bucket = 7;
    return f;
}
}  // namespace

TEST_CASE("field rules: reserved bits, dmethod 5, len_bucket 1..65, actor, digest/dmethod, C3 granularity") {
    CHECK(check_record_fields(grp()) == Reason::none);
    auto f = grp(); f.dmethod = L::kDmethodReservedBatched; CHECK(check_record_fields(f) == Reason::e_dmethod);
    f = grp(); f.dmethod = 0; CHECK(check_record_fields(f) == Reason::e_dmethod);
    f = grp(); f.len_bucket = 65; CHECK(check_record_fields(f) == Reason::none);
    f = grp(); f.len_bucket = 66; CHECK(check_record_fields(f) == Reason::e_field);
    f = grp(); f.sflags = 1; CHECK(check_record_fields(f) == Reason::e_reserved);
    f = grp(); f.reserved1 = 1; CHECK(check_record_fields(f) == Reason::e_reserved);
    f = grp(); f.dmode = 1; CHECK(check_record_fields(f) == Reason::e_dmode);
    f = grp(); f.digest = Hash{}; CHECK(check_record_fields(f) == Reason::e_dmethod);
    f = grp(); f.dmethod = L::kDmKeyedFailed; CHECK(check_record_fields(f) == Reason::e_dmethod);   // dm4 needs zero digest
    f.digest = Hash{}; CHECK(check_record_fields(f) == Reason::none);
    f = grp(); f.actor_class = 5; CHECK(check_record_fields(f) == Reason::e_actor);
    f = grp(); f.actor_uid = 3; CHECK(check_record_fields(f) == Reason::e_field);   // 16 has no actor uid
    f = grp(); f.subj_last = 0; CHECK(check_record_fields(f) == Reason::e_field);
    f = grp(); f.seq = L::kSeqInvalid; CHECK(check_record_fields(f) == Reason::e_seq);
    f = grp(); f.epoch = L::kEpochInvalid; CHECK(check_record_fields(f) == Reason::e_epoch);
    f = grp(); f.event_code = 99; CHECK(check_record_fields(f) == Reason::e_event_code);
    RecordFields t;
    t.rec_type = L::kRtEvent; t.event_code = K::recv_transfer_start; t.dmethod = L::kDmNotApplicable; t.rec_len = 180;
    t.ts_ms = 1500; CHECK(check_record_fields(t) == Reason::e_ts_gran);
    t.ts_ms = 2000; CHECK(check_record_fields(t) == Reason::none);
    RecordFields e;   // 23 exact total only with >= 32 frames
    e.rec_type = L::kRtEvent; e.event_code = K::recv_transfer_end; e.dmethod = L::kDmNotApplicable; e.rec_len = 180;
    e.count = 31; e.bytes = 100; CHECK(check_record_fields(e) == Reason::e_field);
    e.count = 32; CHECK(check_record_fields(e) == Reason::none);
    RecordFields c;   // 73 needs actor staff
    c.rec_type = L::kRtEvent; c.event_code = K::commissioning_verified; c.dmethod = L::kDmNotApplicable; c.rec_len = 180;
    CHECK(check_record_fields(c) == Reason::e_actor);
    RecordFields s;   // signed: ext_reserved must be 0; sflags bits 3-7 must be 0
    s.rec_type = L::kRtCheckpoint; s.event_code = K::checkpoint; s.reason = 1; s.dmethod = L::kDmNotApplicable;
    s.dmode = L::kDmodeKeyed; s.rec_len = 316; s.subj_first = 0; s.subj_last = 3; s.count = 3;
    CHECK(check_record_fields(s) == Reason::none);
    s.ext_reserved = 1; CHECK(check_record_fields(s) == Reason::e_reserved);
    s.ext_reserved = 0; s.sflags = 8; CHECK(check_record_fields(s) == Reason::e_reserved);
    s.sflags = L::kSflagDigestFailed; CHECK(check_record_fields(s) == Reason::e_flag);   // bit2 without dfail_total
    s.dfail_total = 1; CHECK(check_record_fields(s) == Reason::none);
    s.dmode = 0; CHECK(check_record_fields(s) == Reason::e_dmode);
}

TEST_CASE("--pubkeys parser: strict format") {
    Builder b;
    std::string err;
    CHECK(parse_pubkeys(b.pubkeys(), err));
    CHECK_FALSE(parse_pubkeys("", err));
    CHECK_FALSE(parse_pubkeys("ct01-audit-pubkeys v1\n", err));   // no keys
    CHECK_FALSE(parse_pubkeys("ct01-audit-pubkeys v2\n" + b.line(0, 0, "open", true), err));
    std::string l0 = b.line(0, 0, "10", true);
    CHECK_FALSE(parse_pubkeys("ct01-audit-pubkeys v1\n" + l0 + l0, err));   // duplicate epoch
    std::string bad = l0;
    bad[bad.find("pub=") + 6] ^= 1;
    CHECK_FALSE(parse_pubkeys("ct01-audit-pubkeys v1\n" + bad, err));   // point not on curve / bad hex
    CHECK_FALSE(parse_pubkeys("ct01-audit-pubkeys v1\n" + b.line(0, 5, "4", true), err));   // first > last
    CHECK_FALSE(parse_pubkeys("ct01-audit-pubkeys v1\n" + l0 + " extra=1\n", err));
    auto k = parse_pubkeys("ct01-audit-pubkeys v1\n# c\n\n" + b.line(0, 0, "open", false), err);
    REQUIRE(k);
    CHECK_FALSE(k->entries[0].key_id_pinned);
    CHECK(k->entries[0].last == UINT64_MAX);
}

TEST_CASE("--anchor / --epoch-key / u64 parsers") {
    const std::string link(64, 'a'), cid(32, 'b');
    auto a = parse_anchor("7:" + link + ":" + cid);
    REQUIRE(a);
    CHECK(a->seq == 7);
    CHECK_FALSE(parse_anchor("7:" + link));
    CHECK_FALSE(parse_anchor("07:" + link + ":" + cid));
    CHECK_FALSE(parse_anchor("x:" + link + ":" + cid));
    CHECK_FALSE(parse_anchor("7:" + link.substr(1) + ":" + cid));
    CHECK(parse_tag_root(std::string(64, '1')));
    CHECK(parse_tag_root(std::string(64, '1') + "\n"));
    CHECK_FALSE(parse_tag_root(std::string(63, '1')));
    CHECK_FALSE(parse_tag_root(std::string(64, 'g')));
    std::uint64_t v = 0;
    CHECK(parse_u64("18446744073709551615", v));
    CHECK(v == UINT64_MAX);
    CHECK_FALSE(parse_u64("18446744073709551616", v));
    CHECK_FALSE(parse_u64("", v));
    CHECK(parse_epoch_number("4294967294"));
}
