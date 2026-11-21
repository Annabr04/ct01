// audit_chain record codec and per-record (context-free) field rules.
// Every offset/size/rule comes from audit_record_layout.hpp.
#pragma once

#include "ct01/audit_record_layout.hpp"
#include "ct01/audit_result.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace ct01::audit {

namespace crypto { class TestOnlyP256Signer; }

using Hash = layout::Hash;
using ChainId = layout::ChainId;
using RecordFields = layout::RecordFields;
using RecordBytes = std::vector<std::uint8_t>;

// Header parse (5.3 "header parse"): magic, version, rec_type, rec_len == size for the type.
struct HeaderParse {
    Reason reason = Reason::none;   // none = parseable
    std::size_t rec_len = 0;        // valid only when parseable
};
// Needs n >= kHeaderParseSize; returns e_short otherwise.
HeaderParse parse_header(const std::uint8_t* p, std::size_t n);

// Encode all fields (incl. tag/sig/crc32 as given) into exactly record_size_for(rec_type) bytes.
RecordBytes encode_record(const RecordFields& f);
// Decode a full record; the caller guarantees n >= record_size_for(p[kOffRecType]).
RecordFields decode_record(const std::uint8_t* p, std::size_t n);

bool crc_ok(const std::uint8_t* rec, std::size_t rec_len);
std::uint32_t compute_crc(const std::uint8_t* rec, std::size_t rec_len);

// h_n = SHA-256(DS_LINK || chain_id || body_n with the EVENT digest zeroed) (4.1).
Hash compute_link(const ChainId& chain_id, const std::uint8_t* rec, std::size_t rec_len);
// tag_n = HMAC-SHA256(K_e, DS_TAG || h_n || digest_n).
Hash compute_tag(const Hash& epoch_key, const Hash& link, const Hash& digest);
// SHA-256 of the fixed 56-byte pre-image DS_CKPT || h_n (what the TPM signs).
Hash signed_message_digest(const Hash& link);
// K_e = HKDF-SHA256(salt = chain_id, IKM = R^t_e, info = DS_EPOCH_KEY || u32le(e), L = 32).
Hash derive_epoch_key(const ChainId& chain_id, const Hash& tag_root, std::uint32_t epoch);
// d_agg (CHECKPOINT) = SHA-256(DS_AGG || digests...) (4.3).
Hash compute_dagg(const std::vector<Hash>& digests);
// 71 digest = SHA-256(DS_TPMREC || h of the last dmethod-1 record before the failure).
Hash compute_tpmrec(const Hash& last_keyed_link);
// Key id of a software P-256 key = SHA-256(SEC1 uncompressed point). PROVISIONAL: the DESIGN
// does not define the key id derivation; the verifier only ever compares against --pubkeys.
Hash software_key_id(const std::array<std::uint8_t, 65>& sec1);

bool is_zero(const Hash& h);

// Context-free field rules of one record (4.1 rule column, 4.2 per-code columns,
// 6.2 GENESIS consistency). Chain rules (seq, epoch, dmode vs dmethod, link, counters)
// are the verifier's. Returns Reason::none when the record passes.
Reason check_record_fields(const RecordFields& f);

// Seal: computes link, tag (when epoch_key given), signature (signed types, when signer
// given) and CRC; returns the record bytes. Used by the writer and by tests.
struct Sealed {
    RecordBytes bytes;
    Hash link{};
};
Sealed seal_record(RecordFields f, const ChainId& chain_id, const Hash* epoch_key,
                   const crypto::TestOnlyP256Signer* signer);

}  // namespace ct01::audit
