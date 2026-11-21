// Prints the layout header's field table in the format of tests/spec/layout_v0_3_4.log.
#include "ct01/audit_record_layout.hpp"

#include <cstdio>

int main() {
    namespace L = ct01::audit::layout;
    std::printf("common body %zu | EVENT %zu | signed body %zu | SIGNED %zu\n", L::kBodySize, L::kEventRecordSize,
                L::kSignedBodySize, L::kSignedRecordSize);
    for (const auto& f : L::kFieldTable)
        std::printf("%4zu %3zu %.*s\n", f.offset, f.size, static_cast<int>(f.name.size()), f.name.data());
    return 0;
}
