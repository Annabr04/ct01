// Writes the committed seed corpora (run once; outputs are checked in under tests/fuzz/corpus/).
//   make_seeds OUT_DIR   -> OUT_DIR/record_parse/*, OUT_DIR/chain_verify/*
#include "fuzz_common.hpp"

#include <fstream>
#include <string>

using namespace ct01::audit;
namespace L = ct01::audit::layout;

namespace {
void put(const std::string& p, const std::vector<std::uint8_t>& b) {
    std::ofstream(p, std::ios::binary).write(reinterpret_cast<const char*>(b.data()), static_cast<std::streamsize>(b.size()));
}
std::vector<std::uint8_t> chain(int variant) {
    MemorySink sink;
    ChainWriter::GenesisParams gp;
    gp.chain_id = fuzz::chain_id();
    WriteError e;
    const std::uint8_t dmode = variant == 1 ? L::kDmodeAbsent : L::kDmodeKeyed;
    auto w = ChainWriter::create(sink, gp, {&fuzz::signer(0), fuzz::root(0), dmode}, e);
    std::uint64_t fwd = 0, t = 1000;
    auto grp = [&] {
        RecordFields f;
        f.event_code = codes::code::recv_group_delivered;
        f.actor_class = L::kActorReceiver;
        f.subj_first = fwd + 1;
        f.subj_last = fwd + 32;
        fwd += 32;
        f.count = 32;
        f.len_bucket = 7;
        f.dmethod = dmode == L::kDmodeKeyed ? L::kDmKeyed : L::kDmAbsent;
        if (dmode == L::kDmodeKeyed) f.digest.fill(static_cast<std::uint8_t>(fwd));
        f.ts_ms = f.mono_ms = (t += 40);
        w->append_event(f);
    };
    for (int i = 0; i < 4; ++i) grp();
    w->checkpoint(1, t, t);
    if (variant == 2) {
        RecordFields v;
        v.event_code = codes::code::audit_space_level;
        v.reason = 2;
        v.dmethod = L::kDmNotApplicable;
        w->append_event(v);
        grp();
        w->checkpoint(2, t, t);
    }
    grp();
    std::vector<std::uint8_t> out;
    for (const auto& f : sink.files()) out.insert(out.end(), f.bytes.begin(), f.bytes.end());
    return out;
}
}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) return 1;
    const std::string d = argv[1];
    for (int v = 0; v < 3; ++v) {
        auto c = chain(v);
        put(d + "/record_parse/chain" + std::to_string(v), c);
        put(d + "/record_parse/genesis" + std::to_string(v), std::vector<std::uint8_t>(c.begin(), c.begin() + 316));
        put(d + "/record_parse/event" + std::to_string(v), std::vector<std::uint8_t>(c.begin() + 316, c.begin() + 496));
        for (std::uint8_t mode : {0, 1, 3, 5, 9}) {
            std::vector<std::uint8_t> in{mode, 2};
            in.insert(in.end(), c.begin(), c.end());
            put(d + "/chain_verify/v" + std::to_string(v) + "_m" + std::to_string(mode), in);
        }
        std::vector<std::uint8_t> torn{1, 0};
        torn.insert(torn.end(), c.begin(), c.end() - 50);
        put(d + "/chain_verify/v" + std::to_string(v) + "_torn", torn);
    }
    return 0;
}
