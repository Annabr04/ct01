// Writer library (memory + segment-file sinks), JSON/JSONL output hygiene, and the CLI's exit codes.
#include "doctest.h"
#include "test_support.hpp"

#include "ct01/audit_json.hpp"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace ct01::audit;
using namespace ct01::audit::test;
namespace L = ct01::audit::layout;
namespace K = ct01::audit::codes::code;

namespace {
struct TmpDir {
    std::string path;
    TmpDir() {
        char t[] = "/tmp/audit_chain_test_XXXXXX";
        path = ::mkdtemp(t);
    }
    ~TmpDir() { std::system(("rm -rf '" + path + "'").c_str()); }
};
RecordFields group_fields(std::uint64_t sf, std::uint32_t frames, std::uint8_t dm) {
    RecordFields f;
    f.event_code = K::recv_group_delivered;
    f.actor_class = L::kActorReceiver;
    f.subj_first = sf;
    f.subj_last = sf + frames - 1;
    f.count = frames;
    f.len_bucket = 7;
    f.dmethod = dm;
    if (dm == L::kDmKeyed) f.digest = filled(static_cast<std::uint8_t>(sf));
    f.ts_ms = f.mono_ms = 1000 + sf;
    return f;
}
struct Written {
    std::vector<ChainFile> files;
    PubKeyList keys;
    Hash rt0;
};
Written write_chain(int groups, std::uint64_t roll = L::kSegmentRollBytes) {
    static const auto s0 = test_signer(41);
    MemorySink sink(roll);
    ChainWriter::GenesisParams gp;
    gp.chain_id = ChainId{};
    gp.chain_id[0] = 0x77;
    Written w;
    w.rt0 = filled(0x44);
    EpochKeys k{&s0, w.rt0, L::kDmodeKeyed};
    WriteError e;
    auto cw = ChainWriter::create(sink, gp, k, e);
    REQUIRE(cw);
    for (int i = 0; i < groups; ++i) {
        REQUIRE(cw->append_event(group_fields(1 + 32ull * i, 32, L::kDmKeyed)) == WriteError::none);
        if (i % 7 == 6) REQUIRE(cw->checkpoint(1, 5000 + i, 5000 + i) == WriteError::none);
    }
    REQUIRE(cw->checkpoint(3, 9000, 9000) == WriteError::none);
    w.files = sink.files();
    w.keys = keys_of(pubkeys_text({{0, 0, std::nullopt, &s0}}));
    return w;
}
int run_cli(const std::string& args, std::string& out) {
    const std::string cmd = std::string(AUDIT_CLI_PATH) + " " + args + " 2>/dev/null";
    FILE* p = ::popen(cmd.c_str(), "r");
    REQUIRE(p);
    char buf[4096];
    out.clear();
    std::size_t n;
    while ((n = std::fread(buf, 1, sizeof buf, p)) > 0) out.append(buf, n);
    const int st = ::pclose(p);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}
void write_file(const std::string& p, const std::vector<std::uint8_t>& b) {
    std::ofstream(p, std::ios::binary).write(reinterpret_cast<const char*>(b.data()), static_cast<std::streamsize>(b.size()));
}
}  // namespace

TEST_CASE("writer: chains verify (keyed and public), segments roll, out-of-scope refused") {
    auto w = write_chain(20);
    VerifyOptions o;
    o.pubkeys = &w.keys;
    o.tag_roots[0] = w.rt0;
    CHECK(verify_chain(w.files, o).exit == 4);
    o.tag_roots.clear();
    CHECK(verify_chain(w.files, o).exit == 4);
    auto rolled = write_chain(20, 1000);   // tiny segments
    CHECK(rolled.files.size() > 3);
    o.pubkeys = &rolled.keys;
    CHECK(verify_chain(rolled.files, o).exit == 4);

    static const auto s0 = test_signer(42);
    MemorySink sink;
    WriteError e;
    ChainWriter::GenesisParams gp;
    gp.reason = 3;
    CHECK_FALSE(ChainWriter::create(sink, gp, {&s0, std::nullopt, L::kDmodeKeyed}, e));
    CHECK(e == WriteError::out_of_scope);
    gp.reason = 1;
    auto cw = ChainWriter::create(sink, gp, {&s0, std::nullopt, L::kDmodeKeyed}, e);
    REQUIRE(cw);
    for (std::uint16_t c : {K::chain_torn_tail_recovered, K::chain_predecessor, K::chain_gap, K::tpm_recovered}) {
        RecordFields f;
        f.event_code = c;
        f.dmethod = L::kDmNotApplicable;
        CHECK(cw->append_event(f) == WriteError::out_of_scope);
    }
    CHECK(cw->append_event(group_fields(1, 32, L::kDmKeyedFailed)) == WriteError::out_of_scope);
    CHECK(cw->append_event(group_fields(1, 32, L::kDmAbsent)) == WriteError::bad_dmethod);   // keyed epoch
    CHECK(cw->checkpoint(codes::reason::checkpoint::recovery, 1, 1) == WriteError::out_of_scope);
    // C3: 22/23 clocks quantised; 23 exact total dropped below 32 frames; overlapping exact totals refused
    RecordFields t;
    t.event_code = K::recv_transfer_end;
    t.dmethod = L::kDmNotApplicable;
    t.subj_first = 1; t.subj_last = 40; t.count = 40; t.bytes = 4000; t.ts_ms = 12345; t.mono_ms = 999;
    CHECK(cw->append_event(t) == WriteError::none);
    t.subj_first = 30; t.subj_last = 70;
    CHECK(cw->append_event(t) == WriteError::overlap);
    t.count = 5;   // below threshold: no exact total -> no overlap rule
    CHECK(cw->append_event(t) == WriteError::none);
    CHECK(cw->checkpoint(1, 2, 2) == WriteError::none);
    auto keys = keys_of(pubkeys_text({{0, 0, std::nullopt, &s0}}));
    VerifyOptions p;
    p.pubkeys = &keys;
    auto r = verify_chain(sink.files(), p);
    CHECK(r.exit == 4);
}

TEST_CASE("writer: epoch rotation produces a verifiable handover with pinned ranges") {
    static const auto s0 = test_signer(51), s1 = test_signer(52);
    MemorySink sink;
    WriteError e;
    ChainWriter::GenesisParams gp;
    auto cw = ChainWriter::create(sink, gp, {&s0, filled(1), L::kDmodeKeyed}, e);
    REQUIRE(cw);
    REQUIRE(cw->append_event(group_fields(1, 32, L::kDmKeyed)) == WriteError::none);
    REQUIRE(cw->rotate_epoch({&s1, filled(2), L::kDmodeAbsent}, 1, 10, 10) == WriteError::none);
    const std::uint64_t es = cw->next_seq() - 1;
    REQUIRE(cw->checkpoint(codes::reason::checkpoint::epoch_post, 11, 11) == WriteError::none);
    REQUIRE(cw->append_event(group_fields(33, 32, L::kDmAbsent)) == WriteError::none);
    REQUIRE(cw->checkpoint(1, 12, 12) == WriteError::none);
    auto keys = keys_of(pubkeys_text({{0, 0, es, &s0}, {1, es + 1, std::nullopt, &s1}}));
    VerifyOptions o;
    o.pubkeys = &keys;
    o.tag_roots = {{0, filled(1)}, {1, filled(2)}};
    auto r = verify_chain(sink.files(), o);
    CHECK(r.exit == 4);
    CHECK(r.epochs.size() == 2);
    // the same chain with epoch 0 pinned too short -> e_epoch
    auto bad = keys_of(pubkeys_text({{0, 0, es - 1, &s0}, {1, es, std::nullopt, &s1}}));
    o.pubkeys = &bad;
    CHECK(verify_chain(sink.files(), o).reason == Reason::e_epoch);
}

TEST_CASE("segment-file sink: 0600 files, closed segments 0400, lock, verifies from disk") {
    TmpDir d;
    static const auto s0 = test_signer(61);
    ChainId id{};
    id[3] = 9;
    std::string err;
    auto sink = SegmentDirSink::open(d.path, id, err, 1000);
    REQUIRE(sink);
    std::string err2;
    CHECK_FALSE(SegmentDirSink::open(d.path, id, err2));   // flock busy
    CHECK(err2 == "chain lock busy");
    WriteError e;
    ChainWriter::GenesisParams gp;
    gp.chain_id = id;
    auto cw = ChainWriter::create(*sink, gp, {&s0, std::nullopt, L::kDmodeKeyed}, e);
    REQUIRE(cw);
    for (int i = 0; i < 10; ++i) REQUIRE(cw->append_event(group_fields(1 + 32ull * i, 32, L::kDmKeyed)) == WriteError::none);
    REQUIRE(cw->checkpoint(1, 1, 1) == WriteError::none);
    const std::string hex = C::to_hex(id);
    std::vector<ChainFile> files;
    for (int i = 0;; ++i) {
        char n[64];
        std::snprintf(n, sizeof n, "chain_%s_%08d.ac", hex.c_str(), i);
        struct stat st {};
        if (::stat((d.path + "/" + n).c_str(), &st) != 0) break;
        std::ifstream f(d.path + "/" + n, std::ios::binary);
        files.push_back({n, std::vector<std::uint8_t>(std::istreambuf_iterator<char>(f), {})});
        const bool newest = ::access((d.path + "/" + n).c_str(), W_OK) == 0;
        (void)newest;
        CHECK(((st.st_mode & 0777) == 0600 || (st.st_mode & 0777) == 0400));
    }
    CHECK(files.size() >= 3);
    struct stat st0 {};
    ::stat((d.path + "/chain_" + hex + "_00000000.ac").c_str(), &st0);
    CHECK((st0.st_mode & 0777) == 0400);
    auto keys = keys_of(pubkeys_text({{0, 0, std::nullopt, &s0}}));
    VerifyOptions o;
    o.pubkeys = &keys;
    CHECK(verify_chain(files, o).exit == 4);
}

TEST_CASE("JSON/JSONL: no digests, tags, raw bytes or paths; reason numbers present; u64 as strings") {
    auto w = write_chain(8);
    VerifyOptions o;
    o.pubkeys = &w.keys;
    o.tag_roots[0] = w.rt0;
    o.collect_records = true;
    auto r = verify_chain(w.files, o);
    REQUIRE(r.exit == 4);
    const std::string rep = report_json(r);
    CHECK(rep.find("\"anchor\":\"none\"") != std::string::npos);
    CHECK(rep.find("\"last_verified_seq\":\"") != std::string::npos);
    CHECK(rep.find("\"verified_against_data\":false") != std::string::npos);
    CHECK(rep.find("chain_") == std::string::npos);
    CHECK(rep.find("/") == std::string::npos);
    for (const auto& v : r.records) {
        const std::string j = record_jsonl(v);
        CHECK(j.find("\"digest\"") == std::string::npos);
        CHECK(j.find("\"tag\"") == std::string::npos);
        CHECK(j.find("\"reason\":") != std::string::npos);
        CHECK(j.find("\"reason_name\":") != std::string::npos);
        CHECK(j.find(C::to_hex(v.f.digest)) == std::string::npos);   // digest value never appears
        CHECK(j.find(C::to_hex(v.f.tag)) == std::string::npos);
        CHECK(j.find("/") == std::string::npos);
        CHECK((j.find("\"d_agg\"") != std::string::npos) == (v.f.rec_type == L::kRtCheckpoint));
    }
    // FAIL report carries the A.1 number
    Builder b;
    b.genesis();
    b.group();
    b.checkpoint();
    b.after_seal = [](std::size_t i, RecordBytes& x) { if (i == 1) x[100] ^= 1; };
    auto f = verify(b, b.build(), true, false);
    CHECK(report_json(f).find("\"reason\":\"e_crc\",\"reason_code\":19") != std::string::npos);
}

TEST_CASE("CLI: exit codes 0/1/2/4/5 and usage errors; stdout has no paths") {
    TmpDir d;
    Builder b;
    b.genesis();
    b.group();
    b.checkpoint();
    const std::string chain = d.path + "/c.ac", keys = d.path + "/k.txt", rt = d.path + "/rt0";
    write_file(chain, b.build());
    std::ofstream(keys) << b.pubkeys();
    std::ofstream(rt) << C::to_hex(b.roots.at(0)) << "\n";
    std::vector<Hash> links;
    b.build(&links);
    const std::string anchor = std::to_string(links.size() - 1) + ":" + C::to_hex(links.back()) + ":" + C::to_hex(b.chain_id);
    std::string out;
    CHECK(run_cli("--pubkeys " + keys + " " + chain, out) == 4);
    CHECK(out.find(d.path) == std::string::npos);
    CHECK(run_cli("--pubkeys " + keys + " --anchor " + anchor + " --epoch-key 0:" + rt + " " + chain, out) == 0);
    CHECK(run_cli("--pubkeys " + keys + " --export-jsonl " + chain, out) == 4);
    int lines = 0;
    for (char c : out) lines += c == '\n';
    CHECK(lines == 4);   // 3 records + summary
    CHECK(run_cli(chain, out) == 1);                                       // no --pubkeys
    CHECK(run_cli("--pubkeys " + keys, out) == 1);                        // no files
    CHECK(run_cli("--pubkeys " + keys + " --checkpoints x " + chain, out) == 1);
    CHECK(run_cli("--pubkeys " + keys + " --bogus " + chain, out) == 1);
    CHECK(run_cli("--pubkeys " + keys + " --anchor 1:zz " + chain, out) == 1);
    CHECK(run_cli("--pubkeys " + keys + " " + d.path + "/missing.ac", out) == 1);
    CHECK(::symlink(chain.c_str(), (d.path + "/link.ac").c_str()) == 0);
    CHECK(run_cli("--pubkeys " + keys + " " + d.path + "/link.ac", out) == 1);   // O_NOFOLLOW
    CHECK(run_cli("--pubkeys " + keys + " " + d.path, out) == 1);                 // not a regular file
    auto bytes = b.build();
    bytes[400] ^= 1;
    write_file(chain, bytes);
    CHECK(run_cli("--pubkeys " + keys + " " + chain, out) == 2);
    b.group();
    write_file(chain, b.build());
    CHECK(run_cli("--pubkeys " + keys + " --anchor " + anchor + " " + chain, out) == 5);
}
