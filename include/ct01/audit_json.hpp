// JSON outputs (DESIGN 6.2 report, 6.4 JSONL export). Fixed key order, u64 as decimal
// strings, enums by fixed name, reason numbers from DESIGN v0.3.4 Appendix A. NEVER: file
// paths, EVENT or signed-record digest fields, tags, raw bytes.
#pragma once

#include "ct01/audit_verify.hpp"

#include <string>

namespace ct01::audit {

std::string report_json(const Report& r);          // one line, no trailing newline
std::string record_jsonl(const VerifiedRecord& v);  // one line, no trailing newline

}  // namespace ct01::audit
