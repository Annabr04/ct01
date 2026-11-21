// Direction (b) of the oracle differential: synthetic chains written by OUR writer library
// (TEST-ONLY software keys, synthetic data, never PHI) for the independent naive verifier.
//   gen_writer_chains OUT_DIR
// Writes OUT_DIR/<name>.ac (single file each: the oracle concatenates files), OUT_DIR/<name>.pubkeys
// (our --pubkeys format), OUT_DIR/<name>.rt<e> (R^t_e hex) and OUT_DIR/manifest.json.
#include "ct01/audit_crypto.hpp"
#include "ct01/audit_writer.hpp"

#include <cstdio>
#include <fstream>
#include <functional>
#include <string>
#include <vector>

using namespace ct01::audit;
namespace c = ct01::audit::crypto;
using namespace ct01::audit::layout;

namespace {
Hash fill(std::uint8_t b) { Hash h; h.fill(b); return h; }
c::TestOnlyP256Signer signer(std::uint8_t tag) {
    Hash d{};
    d[30] = 0x5e;
    d[31] = tag;   // TEST-ONLY scalar
    return *c::TestOnlyP256Signer::from_scalar(d);
}
Hash grp_digest(std::uint64_t sf, std::uint64_t sl) {   // synthetic stand-in for a TPM keyed digest
    std::uint8_t b[16];
    for (int i = 0; i < 8; ++i) { b[i] = static_cast<std::uint8_t>(sf >> (8 * i)); b[8 + i] = static_cast<std::uint8_t>(sl >> (8 * i)); }
    return c::sha256({c::span(std::string_view("TEST-ONLY synthetic group digest")), {b, 16}});
}

struct Gen {
    std::string name;
    MemorySink sink;
    std::optional<ChainWriter> w;
    std::uint64_t fwd = 0, t = 1'700'000'000'000ull;
    std::uint8_t dmode = kDmodeKeyed;
    bool ok = true;
    void check(WriteError e) {
        if (e != WriteError::none) { std::fprintf(stderr, "%s: write error %s\n", name.c_str(), write_error_name(e)); ok = false; }
    }
    void group(std::uint32_t frames = 32) {
        RecordFields f;
        f.event_code = code::recv_group_delivered;
        f.actor_class = kActorReceiver;
        f.subj_first = fwd + 1;
        f.subj_last = fwd + frames;
        f.count = frames;
        f.len_bucket = len_bucket_of(48);
        f.dmethod = dmode == kDmodeKeyed ? kDmKeyed : kDmAbsent;
        if (dmode == kDmodeKeyed) f.digest = grp_digest(f.subj_first, f.subj_last);
        f.ts_ms = t += 37;
        f.mono_ms = t;
        fwd += frames;
        check(w->append_event(f));
    }
    void event(std::uint16_t code_, std::uint16_t reason, std::uint64_t sf = 0, std::uint64_t sl = 0, std::uint32_t count = 0,
               std::uint8_t actor = kActorNone, std::uint32_t uid = 0) {
        RecordFields f;
        f.event_code = code_;
        f.reason = reason;
        f.subj_first = sf;
        f.subj_last = sl;
        f.count = count;
        f.actor_class = actor;
        f.actor_uid = uid;
        f.dmethod = kDmNotApplicable;
        f.ts_ms = t += 1000;
        f.mono_ms = t;
        check(w->append_event(f));
    }
    void ckpt() { t += 5; check(w->checkpoint(codes::reason::checkpoint::cadence_count, t, t)); }
};
}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) { std::fprintf(stderr, "usage: gen_writer_chains OUT_DIR\n"); return 1; }
    const std::string out = argv[1];
    const auto s0 = signer(1), s1 = signer(2);
    const Hash rt0 = fill(0x21), rt1 = fill(0x22);
    std::string manifest = "{\n";
    bool all_ok = true, first = true;

    auto run = [&](const std::string& name, std::uint8_t dmode, bool with_tags, bool rotate,
                   const std::function<void(Gen&)>& body, int expect_keyed_anchor, int expect_public) {
        Gen g;
        g.name = name;
        g.dmode = dmode;
        ChainWriter::GenesisParams gp;
        gp.chain_id = ChainId{};
        for (std::size_t i = 0; i < gp.chain_id.size(); ++i) gp.chain_id[i] = static_cast<std::uint8_t>(0x40 + name.size() + i);
        gp.ts_ms = g.t;
        gp.mono_ms = g.t;
        EpochKeys k0{&s0, with_tags ? std::optional<Hash>(rt0) : std::nullopt, dmode};
        WriteError e;
        g.w = ChainWriter::create(g.sink, gp, k0, e);
        if (!g.w) { std::fprintf(stderr, "%s: genesis %s\n", name.c_str(), write_error_name(e)); all_ok = false; return; }
        body(g);
        std::uint64_t e0_last = UINT64_MAX;
        if (rotate) {
            EpochKeys k1{&s1, with_tags ? std::optional<Hash>(rt1) : std::nullopt, dmode};
            g.t += 5;
            g.check(g.w->rotate_epoch(k1, codes::reason::epoch_start::scheduled, g.t, g.t));
            e0_last = g.w->next_seq() - 1;   // EPOCH_START, signed by S_0
            g.t += 5;
            g.check(g.w->checkpoint(codes::reason::checkpoint::epoch_post, g.t, g.t));
            for (int i = 0; i < 5; ++i) g.group();
            g.ckpt();
        }
        all_ok &= g.ok;
        std::vector<std::uint8_t> bytes;
        for (const auto& f : g.sink.files()) bytes.insert(bytes.end(), f.bytes.begin(), f.bytes.end());
        std::ofstream(out + "/" + name + ".ac", std::ios::binary).write(reinterpret_cast<const char*>(bytes.data()),
                                                                       static_cast<std::streamsize>(bytes.size()));
        std::vector<PubKeyLine> pk{{0, 0, rotate ? std::optional<std::uint64_t>(e0_last) : std::nullopt, &s0}};
        if (rotate) pk.push_back({1, e0_last + 1, std::nullopt, &s1});
        std::ofstream(out + "/" + name + ".pubkeys") << pubkeys_text(pk);
        std::ofstream(out + "/" + name + ".rt0") << c::to_hex(rt0) << "\n";
        if (rotate) std::ofstream(out + "/" + name + ".rt1") << c::to_hex(rt1) << "\n";
        const std::uint64_t head = g.w->next_seq() - 1;
        manifest += std::string(first ? "" : ",\n") + " \"" + name + "\": {\"sec1\": {\"0\": \"" + c::to_hex(s0.public_sec1()) + "\"" +
                    (rotate ? ", \"1\": \"" + c::to_hex(s1.public_sec1()) + "\"" : "") + "}, \"rt\": {\"0\": \"" + c::to_hex(rt0) + "\"" +
                    (rotate ? ", \"1\": \"" + c::to_hex(rt1) + "\"" : "") + "}, \"tags\": " + (with_tags ? "true" : "false") +
                    ", \"anchor_seq\": " + std::to_string(head) + ", \"anchor_link\": \"" + c::to_hex(g.w->head_link()) +
                    "\", \"chain_id\": \"" + c::to_hex(g.w->chain_id()) + "\", \"expect_keyed_anchor\": " +
                    std::to_string(expect_keyed_anchor) + ", \"expect_public\": " + std::to_string(expect_public) + "}";
        first = false;
    };

    // 1. clean keyed chain, periodic checkpoints
    run("w_clean_keyed", kDmodeKeyed, true, false, [](Gen& g) {
        for (int i = 0; i < 30; ++i) { g.group(); if (i % 10 == 9) g.ckpt(); }
    }, 0, 4);
    // 2. dmode 2 (digest absent): d_agg over all-zero digests (F71)
    run("w_dmode_absent", kDmodeAbsent, true, false, [](Gen& g) {
        for (int i = 0; i < 12; ++i) g.group();
        g.ckpt();
    }, 0, 4);
    // 3. epoch handover 0 -> 1 (CHECKPOINT, EPOCH_START, CHECKPOINT; pinned ranges)
    run("w_epoch_handover", kDmodeKeyed, true, true, [](Gen& g) {
        for (int i = 0; i < 8; ++i) g.group();
        g.ckpt();
        for (int i = 0; i < 3; ++i) g.group();
    }, 0, 4);
    // 4. mixed records: VOID, transfer start/end (C3 quantised), 68 reset, 75 ladder 2 -> 1, 20 fault + 69 ack
    run("w_mixed_events", kDmodeKeyed, true, false, [](Gen& g) {
        g.group();
        g.event(code::recv_transfer_start, codes::reason::recv_transfer_start::normal, 1, 1, 0);
        g.group();
        g.fwd += 1;
        g.event(code::recv_void, codes::reason::recv_void::normal, g.fwd, g.fwd, 1);
        g.group();
        g.event(code::recv_transfer_end, codes::reason::recv_transfer_end::normal, 1, g.fwd, 64);
        g.event(code::recv_coverage, codes::reason::recv_coverage::group_rolled_back, g.fwd - 31, g.fwd, 0);
        g.fwd -= 32;
        g.group();   // re-uses the rolled-back seqs after the 68 reset: no warning
        g.ckpt();
        g.event(code::audit_space_level, codes::reason::audit_space_level::level2);
        g.event(code::audit_space_level, codes::reason::audit_space_level::level1);
        const std::uint64_t fault_seq = g.w->next_seq();
        g.event(code::recv_log_fault, codes::reason::recv_log_fault::io, 0, 0, 0);
        g.event(code::fault_ack, codes::reason::fault_ack::fault, fault_seq, fault_seq, 0, kActorStaff, 1001);
        g.group();
        g.ckpt();
    }, 0, 4);
    // 5. unsigned tail after the last checkpoint: public mode -> 5, keyed (tags) -> covered
    run("w_tail", kDmodeKeyed, true, false, [](Gen& g) {
        for (int i = 0; i < 4; ++i) g.group();
        g.ckpt();
        for (int i = 0; i < 2; ++i) g.group();
    }, 0, 5);
    // 6. no tags at all (writer without R^t): keyed oracle mode cannot be used; public only
    run("w_untagged", kDmodeKeyed, false, false, [](Gen& g) {
        for (int i = 0; i < 4; ++i) g.group();
        g.ckpt();
    }, -1, 4);
    manifest += "\n}\n";
    std::ofstream(out + "/manifest.json") << manifest;
    return all_ok ? 0 : 1;
}
