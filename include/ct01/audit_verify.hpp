// audit_chain verifier (DESIGN 6.2): ONE implementation shared by the CLI
// (tools/ct01_audit_verify.cpp) and the device self-check path (device_self_check).
// Read-only: never creates keys, never modifies input. Exit code via exit_code_for().
#pragma once

#include "ct01/audit_inputs.hpp"
#include "ct01/audit_record.hpp"
#include "ct01/audit_result.hpp"

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace ct01::audit {

struct ChainFile {
    std::string name;                   // basename, used ONLY for ordering / chain_id cross-check; never output
    std::vector<std::uint8_t> bytes;
};

struct VerifyOptions {
    const PubKeyList* pubkeys = nullptr;                 // REQUIRED: the only key source
    std::optional<Anchor> anchor;
    std::map<std::uint32_t, Hash> tag_roots;   // TEST-ONLY R^t_e (--epoch-key); K_e derived with the chain_id
    std::map<std::uint32_t, Hash> tag_keys;    // K_e held by the device (self-check path)
    bool collect_records = false;              // keep verified records for --export-jsonl
};

struct VerifyWarning { std::string code; std::uint64_t seq = 0; };
struct EpochSummary {
    std::uint32_t epoch = 0;
    std::uint8_t dmode = 0;              // 0 = unknown (pruned start)
    std::uint64_t first_seq = 0, last_seq = 0, records = 0;
    bool tag_checked = false;            // a tag key was available for this epoch
};
struct VerifiedRecord { RecordFields f; Hash link{}; bool tag_verified = false; };

inline constexpr std::size_t kMaxWarnings = 100;
inline constexpr std::size_t kMaxEpochs = 64;

struct Report {
    Outcome outcome;
    int exit = exit_code::io_usage;
    Reason reason = Reason::none;
    std::string io_error;                          // stderr only (may name a path in the CLI)
    std::optional<std::uint64_t> first_bad_seq, last_verified_seq, last_signed_seq, tail_unverified_from;
    std::uint64_t torn_bytes = 0;
    std::uint32_t recoveries_total = 0, gaps_total = 0, dfail_total = 0;   // newest signed record
    std::uint8_t newest_sflags = 0;
    bool anchor_given = false, anchor_matched = false;
    std::uint64_t anchor_seq = 0;
    std::optional<std::uint64_t> records_after_anchor;
    std::vector<EpochSummary> epochs;
    std::uint64_t epochs_total = 0;
    std::vector<VerifyWarning> warnings;
    std::uint64_t warnings_total = 0;
    std::uint64_t keyed_records = 0, absent_records = 0, failed_records = 0;
    std::uint64_t records_verified = 0;
    bool pruned_start = false;
    bool keyed_mode = false;                       // at least one tag key supplied
    std::optional<std::uint64_t> first_ts_ms, last_ts_ms;   // writer_reported
    std::vector<VerifiedRecord> records;           // when collect_records
    std::vector<std::string> qualifiers() const;
};

Report verify_chain(const std::vector<ChainFile>& files, const VerifyOptions& opt);

// Device self-check path (on-device, K_e in RAM): same verifier, same precedence.
Report device_self_check(const std::vector<ChainFile>& segments, const PubKeyList& pubkeys,
                         const std::map<std::uint32_t, Hash>& epoch_tag_keys, const std::optional<Anchor>& anchor);

}  // namespace ct01::audit
