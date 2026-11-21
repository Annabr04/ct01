// audit_chain verification outcome: reason codes, exit codes (DESIGN 6.2, a STABLE API),
// and THE precedence function shared by the device self-check path and the CLI.
#pragma once

#include <cstdint>
#include <string_view>

#include "ct01/codes.hpp"

namespace ct01::audit {

// Reason (FAIL reasons e_*, DESIGN v0.3.4 Appendix A.1, frozen numbers) comes from codes.hpp.
std::string_view reason_name(Reason r);

// Exit codes (6.2). 7-9 are reserved and never emitted.
namespace exit_code {
inline constexpr int ok = 0;
inline constexpr int io_usage = 1;
inline constexpr int fail = 2;
inline constexpr int ok_torn_tail = 3;
inline constexpr int ok_unanchored = 4;
inline constexpr int ok_tail_unverified = 5;
inline constexpr int ok_recovered = 6;
inline constexpr int reserved_min = 7;
inline constexpr int reserved_max = 9;
}  // namespace exit_code

// A qualified accept is 3 <= rc <= 6 (never rc <= 6, which would accept 1 and 2).
constexpr bool is_qualified_accept(int rc) { return rc >= exit_code::ok_torn_tail && rc <= exit_code::ok_recovered; }
constexpr bool is_accept(int rc) { return rc == exit_code::ok || is_qualified_accept(rc); }

// Everything the precedence needs. Several qualifiers can hold at once.
struct Outcome {
    bool io_or_usage_error = false;
    bool fail = false;
    // exit 6, all read from the NEWEST signed record (permanent, survive pruning):
    bool recovered = false;        // recoveries_total > 0
    bool gap = false;              // gaps_total > 0
    bool successor = false;        // sflags bit1 (A009 F49)
    bool digest_failed = false;    // sflags bit2 / dfail_total > 0 (A009 F52, A010 F60)
    bool tail_unverified = false;  // records after the last signature not covered by a verified tag
    bool unanchored = false;       // no --anchor
    bool torn_tail = false;        // unrecovered torn stub in the newest file
};

// THE precedence function: 1 > 2 > first applicable of 6, 5, 4, 3 > 0.
constexpr int exit_code_for(const Outcome& o) {
    if (o.io_or_usage_error) return exit_code::io_usage;
    if (o.fail) return exit_code::fail;
    if (o.recovered || o.gap || o.successor || o.digest_failed) return exit_code::ok_recovered;
    if (o.tail_unverified) return exit_code::ok_tail_unverified;
    if (o.unanchored) return exit_code::ok_unanchored;
    if (o.torn_tail) return exit_code::ok_torn_tail;
    return exit_code::ok;
}

std::string_view result_name(int rc);   // "ok", "io_error", "FAIL", "ok_torn_tail", ...

}  // namespace ct01::audit
