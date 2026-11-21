// Crypto known-answer tests and layout invariants (all sizes/offsets from the ONE layout header).
#include "doctest.h"
#include "test_support.hpp"

#include <cstring>

using namespace ct01::audit;
namespace L = ct01::audit::layout;
namespace C = ct01::audit::crypto;

namespace {
std::vector<std::uint8_t> hx(const std::string& h) {
    std::vector<std::uint8_t> v(h.size() / 2);
    REQUIRE(C::from_hex(h, v.data(), v.size()));
    return v;
}
}  // namespace

TEST_CASE("SHA-256 / HMAC-SHA256 (RFC 4231 TC2) / HKDF (RFC 5869 TC1) / CRC-32 KATs") {
    CHECK(C::to_hex(C::sha256({C::span(std::string_view("abc"))})) ==
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK(C::to_hex(C::hmac_sha256(C::span(std::string_view("Jefe")), {C::span(std::string_view("what do ya want for nothing?"))})) ==
          "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    auto ikm = hx("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), salt = hx("000102030405060708090a0b0c"),
         info = hx("f0f1f2f3f4f5f6f7f8f9");
    auto okm = C::hkdf_sha256(C::span(salt), C::span(ikm), C::span(info), 42);
    CHECK(C::to_hex(okm.data(), okm.size()) ==
          "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
    const char* s = "123456789";
    CHECK(C::crc32_ieee(reinterpret_cast<const std::uint8_t*>(s), 9) == 0xCBF43926u);
}

TEST_CASE("ECDSA P-256: RFC 6979 A.2.5 vector verifies raw; low-s rule; test signer round trip") {
    // RFC 6979 A.2.5 public key and the SHA-256 signature of "sample".
    auto ux = hx("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6");
    auto uy = hx("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299");
    C::Point65 pt{};
    pt[0] = 4;
    std::memcpy(pt.data() + 1, ux.data(), 32);
    std::memcpy(pt.data() + 33, uy.data(), 32);
    auto pk = C::P256PublicKey::from_sec1(pt);
    REQUIRE(pk);
    C::Sig64 sig{};
    auto r = hx("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716");
    auto sv = hx("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8");
    std::memcpy(sig.data(), r.data(), 32);
    std::memcpy(sig.data() + 32, sv.data(), 32);
    const auto digest = C::sha256({C::span(std::string_view("sample"))});
    CHECK(pk->verify_prehashed(digest, sig));
    CHECK_FALSE(C::sig_scalars_in_range(sig));   // s > n/2: high-s, rejected by the v1 rule
    auto signer = ct01::audit::test::test_signer(9);
    auto s2 = signer.sign_prehashed(digest);
    REQUIRE(s2);
    CHECK(C::sig_scalars_in_range(*s2));
    auto pk2 = C::P256PublicKey::from_sec1(signer.public_sec1());
    REQUIRE(pk2);
    CHECK(pk2->verify_prehashed(digest, *s2));
    pt[40] ^= 1;   // off-curve point rejected
    CHECK_FALSE(C::P256PublicKey::from_sec1(pt));
}

TEST_CASE("layout: sizes and offsets derived from the header, contiguous and aligned") {
    static_assert(L::kEventRecordSize == 180 && L::kSignedRecordSize == 316 && L::kSignedBodySize == 216);
    std::size_t end_common = 0, end_signed = 0;
    for (const auto& f : L::kFieldTable) {
        CHECK(f.offset % (f.size >= 8 ? 8 : f.size) == 0);
        if (f.offset < L::kBodySize) end_common = std::max(end_common, f.offset + f.size);
        end_signed = std::max(end_signed, f.offset + f.size);
    }
    CHECK(end_common == L::kBodySize);
    CHECK(end_signed == L::kSignedRecordSize);
    // fields tile [0, 316) without gaps in the signed record
    std::vector<int> cover(L::kSignedRecordSize, 0);
    for (const auto& f : L::kFieldTable)
        for (std::size_t i = 0; i < f.size; ++i) ++cover[f.offset + i];
    for (int c : cover) CHECK(c == 1);
    CHECK(L::kOffDfailTotal == 176);
    CHECK(L::kOffDagg == 184);
    CHECK(L::kSignedPreimageSize == L::kDsCkpt.size() + L::kHashSize);
    for (std::size_t i = 0; i < L::kAllLabels.size(); ++i)
        for (std::size_t j = 0; j < L::kAllLabels.size(); ++j)
            if (i != j) CHECK(L::kAllLabels[j].substr(0, L::kAllLabels[i].size()) != L::kAllLabels[i]);   // prefix-free
    CHECK(L::len_bucket_of(0) == 0);
    CHECK(L::len_bucket_of(1) == 1);
    CHECK(L::len_bucket_of(48) == 7);
    CHECK(L::len_bucket_of((1ull << 32) + 1) == 34);
}

TEST_CASE("encode/decode round trip for every field; link zeroes the EVENT digest only") {
    RecordFields f;
    f.rec_type = L::kRtCheckpoint;
    f.event_code = 2;
    f.rec_len = 316;
    f.reason = 3;
    f.seq = 0x0102030405060708ull;
    f.epoch = 9;
    f.ts_ms = 11;
    f.digest = ct01::audit::test::filled(0xaa);
    f.dfail_total = 5;
    f.d_agg = ct01::audit::test::filled(0xbb);
    auto b = encode_record(f);
    REQUIRE(b.size() == 316);
    auto g = decode_record(b.data(), b.size());
    CHECK(g.seq == f.seq);
    CHECK(g.dfail_total == 5);
    CHECK(g.d_agg == f.d_agg);
    CHECK(g.digest == f.digest);
    ChainId id{};
    RecordFields e;
    e.rec_type = L::kRtEvent;
    e.event_code = 16;
    e.rec_len = 180;
    auto eb = encode_record(e);
    const auto h0 = compute_link(id, eb.data(), eb.size());
    eb[L::kOffDigest] ^= 1;
    CHECK(compute_link(id, eb.data(), eb.size()) == h0);   // EVENT digest excluded from the link
    auto sb = encode_record(f);
    const auto s0 = compute_link(id, sb.data(), sb.size());
    sb[L::kOffDigest] ^= 1;
    CHECK(compute_link(id, sb.data(), sb.size()) != s0);   // signed digest (key id) is linked
    sb[L::kOffDagg] ^= 1;
}

TEST_CASE("codes.hpp matches the layout per-code table: same codes, same rec_types") {
    CHECK(L::kEventSpecs.size() == codes::kCodeTables.size());
    for (const auto& t : codes::kCodeTables) {
        const auto* s = L::find_event_spec(t.code);
        REQUIRE(s);
        CHECK(s->rec_type == t.rec_type);
        CHECK(s->name == t.name);
    }
}
