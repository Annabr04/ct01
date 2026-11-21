// libFuzzer target 2: the chain verifier. Byte 0 selects the mode (bit0 keyed, bit1 anchored at a
// fixed point, bit2 split into two files at byte 1 * 180); the rest is the chain. Invariants: exit in
// 0..6 (7-9 never emitted), FAIL <=> reason set, exit == exit_code_for(outcome), JSON builds.
#include "ct01/audit_json.hpp"
#include "ct01/audit_verify.hpp"
#include "fuzz_common.hpp"

#include <cstdlib>

using namespace ct01::audit;

extern "C" unsigned long long fuzz_target_accepted;
unsigned long long fuzz_target_accepted = 0;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size < 2) return 0;
    const std::uint8_t mode = data[0];
    const std::size_t split = std::min<std::size_t>(size - 2, static_cast<std::size_t>(data[1]) * 180);
    const std::uint8_t* body = data + 2;
    const std::size_t n = size - 2;
    std::vector<ChainFile> files;
    if (mode & 4) {
        files.push_back({"a.ac", std::vector<std::uint8_t>(body, body + split)});
        files.push_back({"b.ac", std::vector<std::uint8_t>(body + split, body + n)});
    } else {
        files.push_back({"a.ac", std::vector<std::uint8_t>(body, body + n)});
    }
    VerifyOptions o;
    o.pubkeys = &fuzz::keys();
    if (mode & 1) { o.tag_roots[0] = fuzz::root(0); o.tag_roots[1] = fuzz::root(1); }
    if (mode & 2) o.anchor = Anchor{1, Hash{}, fuzz::chain_id()};
    o.collect_records = (mode & 8) != 0;
    const Report r = verify_chain(files, o);
    if (r.exit < 0 || r.exit > 6) std::abort();
    if (r.exit != exit_code_for(r.outcome)) std::abort();
    if ((r.exit == 2) != (r.reason != Reason::none)) std::abort();
    if (r.warnings.size() > kMaxWarnings || r.epochs.size() > kMaxEpochs) std::abort();
    const std::string j = report_json(r);
    if (j.empty() || j.front() != '{') std::abort();
    for (const auto& v : r.records) (void)record_jsonl(v);
    if (is_accept(r.exit)) ++fuzz_target_accepted;
    return 0;
}
