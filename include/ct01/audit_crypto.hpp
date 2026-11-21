// audit_chain crypto primitives (OpenSSL 3 libcrypto; DESIGN section 1 "Assumptions: OpenSSL").
// SHA-256, HMAC-SHA256, HKDF-SHA256 (RFC 5869), IEEE CRC-32, constant-time compare,
// ECDSA P-256 verification of a prehashed message with r||s big-endian scalars.
// The software P-256 signer is DEV/TEST-ONLY (DESIGN 3.1: refused in Release, never
// accepted by a holder); it is only for M1 software-key tests and the writer library.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ct01::audit::crypto {

using Bytes = std::vector<std::uint8_t>;
using Hash32 = std::array<std::uint8_t, 32>;
using Point65 = std::array<std::uint8_t, 65>;   // SEC1 uncompressed 0x04 || X || Y
using Sig64 = std::array<std::uint8_t, 64>;      // r || s big-endian

// Streaming SHA-256 over several spans.
struct Span { const std::uint8_t* p; std::size_t n; };
inline Span span(std::string_view s) { return {reinterpret_cast<const std::uint8_t*>(s.data()), s.size()}; }
template <std::size_t N> Span span(const std::array<std::uint8_t, N>& a) { return {a.data(), N}; }
inline Span span(const Bytes& b) { return {b.data(), b.size()}; }

Hash32 sha256(std::initializer_list<Span> parts);
Hash32 hmac_sha256(Span key, std::initializer_list<Span> parts);
// HKDF-SHA256 (extract + expand), out_len <= 255*32.
Bytes hkdf_sha256(Span salt, Span ikm, Span info, std::size_t out_len);

std::uint32_t crc32_ieee(const std::uint8_t* p, std::size_t n);
bool ct_equal(const std::uint8_t* a, const std::uint8_t* b, std::size_t n);   // CRYPTO_memcmp

// P-256 group order n (big-endian) and the low-s rule 1 <= r < n, 1 <= s <= n/2 (DESIGN 4.1 sig row).
bool sig_scalars_in_range(const Sig64& sig);

class P256PublicKey {
public:
    // Parses and validates a SEC1 uncompressed point (on-curve check). nullopt on failure.
    static std::optional<P256PublicKey> from_sec1(const Point65& pt);
    // Raw ECDSA verify of a 32-byte message digest; does NOT apply the low-s rule.
    bool verify_prehashed(const Hash32& digest, const Sig64& sig) const;
    const Point65& sec1() const { return pt_; }
    P256PublicKey(const P256PublicKey&);
    P256PublicKey& operator=(const P256PublicKey&);
    P256PublicKey(P256PublicKey&&) noexcept;
    P256PublicKey& operator=(P256PublicKey&&) noexcept;
    ~P256PublicKey();
private:
    P256PublicKey() = default;
    struct Impl;
    std::shared_ptr<Impl> impl_;
    Point65 pt_{};
};

// DEV/TEST-ONLY software signing key (never a production key path).
class TestOnlyP256Signer {
public:
    // Deterministic key from a 32-byte big-endian scalar (1 <= d < n), for reproducible tests.
    static std::optional<TestOnlyP256Signer> from_scalar(const Hash32& d);
    // Signs a 32-byte digest (random k from OpenSSL); returns r||s with s normalised to low-s.
    std::optional<Sig64> sign_prehashed(const Hash32& digest) const;
    const Point65& public_sec1() const { return pub_; }
    TestOnlyP256Signer(const TestOnlyP256Signer&);
    TestOnlyP256Signer& operator=(const TestOnlyP256Signer&);
    ~TestOnlyP256Signer();
private:
    TestOnlyP256Signer() = default;
    struct Impl;
    std::shared_ptr<Impl> impl_;
    Point65 pub_{};
};

std::string to_hex(const std::uint8_t* p, std::size_t n);
template <std::size_t N> std::string to_hex(const std::array<std::uint8_t, N>& a) { return to_hex(a.data(), N); }
// Strict lowercase/uppercase hex of exactly out_len bytes; false on any other input.
bool from_hex(std::string_view hex, std::uint8_t* out, std::size_t out_len);

}  // namespace ct01::audit::crypto
