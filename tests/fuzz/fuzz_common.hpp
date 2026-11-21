// Shared TEST-ONLY fixture for the audit_chain fuzz targets and their seed generator.
#pragma once

#include "ct01/audit_crypto.hpp"
#include "ct01/audit_inputs.hpp"
#include "ct01/audit_writer.hpp"

namespace ct01::audit::fuzz {

inline const crypto::TestOnlyP256Signer& signer(std::uint32_t epoch) {
    static const crypto::TestOnlyP256Signer s0 = [] { Hash d{}; d[30] = 0xf2; d[31] = 1; return *crypto::TestOnlyP256Signer::from_scalar(d); }();
    static const crypto::TestOnlyP256Signer s1 = [] { Hash d{}; d[30] = 0xf2; d[31] = 2; return *crypto::TestOnlyP256Signer::from_scalar(d); }();
    return epoch == 0 ? s0 : s1;
}
inline Hash root(std::uint32_t epoch) { Hash h; h.fill(static_cast<std::uint8_t>(0x60 + epoch)); return h; }
inline ChainId chain_id() { ChainId c; c.fill(0x5c); return c; }
// Epoch 0 open-ended pinned to [0, 2^64-2] unless a rotation seq is given; key ids pinned.
inline const PubKeyList& keys() {
    static const PubKeyList k = [] {
        std::string err;
        auto t = pubkeys_text({{0, 0, std::nullopt, &signer(0)}});
        return *parse_pubkeys(t, err);
    }();
    return k;
}

}  // namespace ct01::audit::fuzz
