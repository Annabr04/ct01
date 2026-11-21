// libFuzzer target 1: the record parser. Walks the input as a chain blob with the 5.3 framing rule,
// decodes each record, runs the context-free field rules, CRC and link/tag computation, and checks
// encode(decode(x)) == x for every record that parses.
#include "ct01/audit_record.hpp"

#include <cstdlib>
#include <cstring>

using namespace ct01::audit;
namespace L = ct01::audit::layout;

extern "C" unsigned long long fuzz_target_accepted;
unsigned long long fuzz_target_accepted = 0;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    std::size_t off = 0;
    const ChainId id{};
    const Hash key{};
    while (off < size) {
        const std::size_t rem = size - off;
        if (rem < L::kHeaderParseSize) break;
        const HeaderParse hp = parse_header(data + off, rem);
        if (hp.reason != Reason::none || rem < hp.rec_len) break;
        if (hp.rec_len != L::kEventRecordSize && hp.rec_len != L::kSignedRecordSize) std::abort();
        const std::uint8_t* p = data + off;
        const RecordFields f = decode_record(p, hp.rec_len);
        const RecordBytes again = encode_record(f);
        if (again.size() != hp.rec_len || std::memcmp(again.data(), p, hp.rec_len) != 0) std::abort();   // lossless
        const bool crc = crc_ok(p, hp.rec_len);
        const Reason r = check_record_fields(f);
        if (static_cast<unsigned>(r) >= static_cast<unsigned>(Reason::count_)) std::abort();
        (void)compute_link(id, p, hp.rec_len);
        (void)compute_tag(key, f.prev_link, f.digest);
        if (crc && r == Reason::none) ++fuzz_target_accepted;
        off += hp.rec_len;
    }
    return 0;
}
