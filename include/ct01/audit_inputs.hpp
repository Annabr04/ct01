// Verifier inputs: --pubkeys file, --anchor, --epoch-key (TEST-ONLY). Parsers are pure
// functions over bytes (fuzzable); the CLI does the file I/O. Keys come ONLY from the
// --pubkeys content passed in: no environment variables, no default paths, no embedded keys.
#pragma once

#include "ct01/audit_crypto.hpp"
#include "ct01/audit_record_layout.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ct01::audit {

// One pinned epoch key. Format (one line per epoch, '#' comments, blank lines ignored;
// first non-comment line must be exactly "ct01-audit-pubkeys v1"):
//   epoch=<u32> first=<u64> last=<u64|open> key_id=<64 hex|unpinned> pub=<130 hex SEC1 uncompressed>
// key_id=unpinned disables the key-id CLAIM checks (GENESIS id prefix, CHECKPOINT signer id,
// EPOCH_START next id) for that epoch and adds a warning; signatures are still verified.
// Used only for third-party vectors that do not carry key ids (reference-oracle vectors).
struct PubKeyEntry {
    std::uint32_t epoch = 0;
    std::uint64_t first = 0;
    std::uint64_t last = UINT64_MAX;   // "open" = current epoch
    layout::Hash key_id{};
    bool key_id_pinned = true;
    crypto::P256PublicKey key;
};
struct PubKeyList {
    std::vector<PubKeyEntry> entries;   // strictly increasing epoch
    const PubKeyEntry* find(std::uint32_t epoch) const;
};
inline constexpr std::size_t kMaxPubKeysFileBytes = 1u << 20;
inline constexpr std::size_t kMaxPubKeyEntries = 4096;
// Returns nullopt + error on any malformed content (strict: unknown keys, duplicates,
// non-increasing epochs, first > last, overlapping ranges beyond one shared seq, bad points).
std::optional<PubKeyList> parse_pubkeys(std::string_view text, std::string& error);

struct Anchor {
    std::uint64_t seq = 0;
    layout::Hash link{};
    layout::ChainId chain_id{};
};
// "seq:link_hex:chain_id_hex" (decimal seq, 64 hex, 32 hex).
std::optional<Anchor> parse_anchor(std::string_view s);

// --epoch-key e:FILE content: exactly 64 hex chars of R^t_e (+ optional trailing newline). TEST-ONLY.
std::optional<std::uint32_t> parse_epoch_number(std::string_view s);
std::optional<layout::Hash> parse_tag_root(std::string_view content);

bool parse_u64(std::string_view s, std::uint64_t& out);

}  // namespace ct01::audit
