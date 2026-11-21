#include "ct01/audit_result.hpp"

#include <array>

namespace ct01::audit {

std::string_view reason_name(Reason r) {
    const auto i = static_cast<std::size_t>(r);
    return i < kReasonNames.size() ? kReasonNames[i] : std::string_view("unknown");
}

std::string_view result_name(int rc) {
    switch (rc) {
        case exit_code::ok: return "ok";
        case exit_code::io_usage: return "io_error";
        case exit_code::fail: return "FAIL";
        case exit_code::ok_torn_tail: return "ok_torn_tail";
        case exit_code::ok_unanchored: return "ok_unanchored";
        case exit_code::ok_tail_unverified: return "ok_tail_unverified";
        case exit_code::ok_recovered: return "ok_recovered";
        default: return "reserved";
    }
}

}  // namespace ct01::audit
