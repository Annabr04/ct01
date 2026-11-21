#include "ct01/audit_crypto.hpp"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/param_build.h>

#include <cstring>
#include <stdexcept>

namespace ct01::audit::crypto {

namespace {
struct MdCtx {
    EVP_MD_CTX* c = EVP_MD_CTX_new();
    ~MdCtx() { EVP_MD_CTX_free(c); }
};
[[noreturn]] void die(const char* what) { throw std::runtime_error(what); }

// P-256 order n, big-endian, and n/2 (floor).
constexpr std::uint8_t kN[32] = {0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51};
constexpr std::uint8_t kHalfN[32] = {0x7F, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                     0xDE, 0x73, 0x7D, 0x56, 0xD3, 0x8B, 0xCF, 0x42, 0x79, 0xDC, 0xE5, 0x61, 0x7E, 0x31, 0x92, 0xA8};

int cmp_be(const std::uint8_t* a, const std::uint8_t* b) { return std::memcmp(a, b, 32); }
bool is_zero(const std::uint8_t* a) { for (int i = 0; i < 32; ++i) if (a[i]) return false; return true; }

EVP_PKEY* pkey_from_point(const Point65& pt) {
    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    if (!bld) return nullptr;
    EVP_PKEY* pkey = nullptr;
    OSSL_PARAM* params = nullptr;
    EVP_PKEY_CTX* ctx = nullptr;
    if (OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0) == 1 &&
        OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pt.data(), pt.size()) == 1 &&
        (params = OSSL_PARAM_BLD_to_param(bld)) != nullptr &&
        (ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr)) != nullptr &&
        EVP_PKEY_fromdata_init(ctx) == 1) {
        if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) != 1) pkey = nullptr;
    }
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    if (!pkey) return nullptr;
    // Explicit public-key check (on curve, not infinity).
    EVP_PKEY_CTX* chk = EVP_PKEY_CTX_new_from_pkey(nullptr, pkey, nullptr);
    const bool ok = chk && EVP_PKEY_public_check(chk) == 1;
    EVP_PKEY_CTX_free(chk);
    if (!ok) { EVP_PKEY_free(pkey); return nullptr; }
    return pkey;
}

bool sig_to_der(const Sig64& sig, Bytes& der) {
    ECDSA_SIG* s = ECDSA_SIG_new();
    if (!s) return false;
    BIGNUM* r = BN_bin2bn(sig.data(), 32, nullptr);
    BIGNUM* ss = BN_bin2bn(sig.data() + 32, 32, nullptr);
    if (!r || !ss || ECDSA_SIG_set0(s, r, ss) != 1) { BN_free(r); BN_free(ss); ECDSA_SIG_free(s); return false; }
    const int len = i2d_ECDSA_SIG(s, nullptr);
    if (len <= 0) { ECDSA_SIG_free(s); return false; }
    der.resize(static_cast<std::size_t>(len));
    unsigned char* p = der.data();
    i2d_ECDSA_SIG(s, &p);
    ECDSA_SIG_free(s);
    return true;
}
}  // namespace

Hash32 sha256(std::initializer_list<Span> parts) {
    MdCtx m;
    if (!m.c || EVP_DigestInit_ex(m.c, EVP_sha256(), nullptr) != 1) die("sha256 init");
    for (const auto& s : parts)
        if (s.n && EVP_DigestUpdate(m.c, s.p, s.n) != 1) die("sha256 update");
    Hash32 out{};
    unsigned n = 0;
    if (EVP_DigestFinal_ex(m.c, out.data(), &n) != 1 || n != 32) die("sha256 final");
    return out;
}

Hash32 hmac_sha256(Span key, std::initializer_list<Span> parts) {
    // HMAC by definition (FIPS 198-1) over SHA-256; avoids the EVP_MAC fetch per call.
    std::uint8_t k0[64] = {};
    if (key.n > 64) { const Hash32 kh = sha256({key}); std::memcpy(k0, kh.data(), 32); }
    else if (key.n) std::memcpy(k0, key.p, key.n);
    std::uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; ++i) { ipad[i] = k0[i] ^ 0x36; opad[i] = k0[i] ^ 0x5c; }
    MdCtx m;
    if (!m.c || EVP_DigestInit_ex(m.c, EVP_sha256(), nullptr) != 1 || EVP_DigestUpdate(m.c, ipad, 64) != 1) die("hmac");
    for (const auto& s : parts)
        if (s.n && EVP_DigestUpdate(m.c, s.p, s.n) != 1) die("hmac");
    Hash32 inner{};
    unsigned n = 0;
    if (EVP_DigestFinal_ex(m.c, inner.data(), &n) != 1) die("hmac");
    Hash32 out = sha256({Span{opad, 64}, span(inner)});
    OPENSSL_cleanse(k0, sizeof k0);
    OPENSSL_cleanse(ipad, sizeof ipad);
    OPENSSL_cleanse(opad, sizeof opad);
    OPENSSL_cleanse(inner.data(), inner.size());
    return out;
}

Bytes hkdf_sha256(Span salt, Span ikm, Span info, std::size_t out_len) {
    if (out_len > 255 * 32) die("hkdf length");
    std::uint8_t zero_salt[32] = {};
    const Span s = salt.n ? salt : Span{zero_salt, 32};
    Hash32 prk = hmac_sha256(s, {ikm});
    Bytes out;
    Hash32 t{};
    std::size_t tlen = 0;
    for (std::uint8_t i = 1; out.size() < out_len; ++i) {
        const std::uint8_t c = i;
        t = hmac_sha256(span(prk), {Span{t.data(), tlen}, info, Span{&c, 1}});
        tlen = 32;
        const std::size_t take = std::min<std::size_t>(32, out_len - out.size());
        out.insert(out.end(), t.begin(), t.begin() + static_cast<std::ptrdiff_t>(take));
    }
    OPENSSL_cleanse(prk.data(), prk.size());
    OPENSSL_cleanse(t.data(), t.size());
    return out;
}

std::uint32_t crc32_ieee(const std::uint8_t* p, std::size_t n) {
    static const auto table = [] {
        std::array<std::uint32_t, 256> t{};
        for (std::uint32_t i = 0; i < 256; ++i) {
            std::uint32_t c = i;
            for (int k = 0; k < 8; ++k) c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            t[i] = c;
        }
        return t;
    }();
    std::uint32_t c = 0xFFFFFFFFu;
    for (std::size_t i = 0; i < n; ++i) c = table[(c ^ p[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

bool ct_equal(const std::uint8_t* a, const std::uint8_t* b, std::size_t n) { return CRYPTO_memcmp(a, b, n) == 0; }

bool sig_scalars_in_range(const Sig64& sig) {
    const std::uint8_t* r = sig.data();
    const std::uint8_t* s = sig.data() + 32;
    if (is_zero(r) || cmp_be(r, kN) >= 0) return false;
    if (is_zero(s) || cmp_be(s, kHalfN) > 0) return false;
    return true;
}

// ---- P256PublicKey ----
struct P256PublicKey::Impl {
    EVP_PKEY* pkey = nullptr;
    ~Impl() { EVP_PKEY_free(pkey); }
};
P256PublicKey::P256PublicKey(const P256PublicKey&) = default;
P256PublicKey& P256PublicKey::operator=(const P256PublicKey&) = default;
P256PublicKey::P256PublicKey(P256PublicKey&&) noexcept = default;
P256PublicKey& P256PublicKey::operator=(P256PublicKey&&) noexcept = default;
P256PublicKey::~P256PublicKey() = default;

std::optional<P256PublicKey> P256PublicKey::from_sec1(const Point65& pt) {
    if (pt[0] != 0x04) return std::nullopt;
    EVP_PKEY* k = pkey_from_point(pt);
    if (!k) return std::nullopt;
    P256PublicKey out;
    out.impl_ = std::make_shared<Impl>();
    out.impl_->pkey = k;
    out.pt_ = pt;
    return out;
}

bool P256PublicKey::verify_prehashed(const Hash32& digest, const Sig64& sig) const {
    if (!impl_ || !impl_->pkey) return false;
    Bytes der;
    if (!sig_to_der(sig, der)) return false;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, impl_->pkey, nullptr);
    bool ok = ctx && EVP_PKEY_verify_init(ctx) == 1 &&
              EVP_PKEY_verify(ctx, der.data(), der.size(), digest.data(), digest.size()) == 1;
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

// ---- TestOnlyP256Signer ----
struct TestOnlyP256Signer::Impl {
    EVP_PKEY* pkey = nullptr;
    ~Impl() { EVP_PKEY_free(pkey); }
};
TestOnlyP256Signer::TestOnlyP256Signer(const TestOnlyP256Signer&) = default;
TestOnlyP256Signer& TestOnlyP256Signer::operator=(const TestOnlyP256Signer&) = default;
TestOnlyP256Signer::~TestOnlyP256Signer() = default;

std::optional<TestOnlyP256Signer> TestOnlyP256Signer::from_scalar(const Hash32& d) {
    if (is_zero(d.data()) || cmp_be(d.data(), kN) >= 0) return std::nullopt;
    EC_GROUP* grp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    BIGNUM* bn = BN_bin2bn(d.data(), 32, nullptr);
    EC_POINT* pub = grp ? EC_POINT_new(grp) : nullptr;
    Point65 pt{};
    bool ok = grp && bn && pub && EC_POINT_mul(grp, pub, bn, nullptr, nullptr, nullptr) == 1 &&
              EC_POINT_point2oct(grp, pub, POINT_CONVERSION_UNCOMPRESSED, pt.data(), pt.size(), nullptr) == pt.size();
    EC_POINT_free(pub);
    EC_GROUP_free(grp);
    EVP_PKEY* pkey = nullptr;
    if (ok) {
        OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
        OSSL_PARAM* params = nullptr;
        EVP_PKEY_CTX* ctx = nullptr;
        ok = bld && OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0) == 1 &&
             OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, bn) == 1 &&
             OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pt.data(), pt.size()) == 1 &&
             (params = OSSL_PARAM_BLD_to_param(bld)) != nullptr &&
             (ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr)) != nullptr &&
             EVP_PKEY_fromdata_init(ctx) == 1 && EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params) == 1;
        EVP_PKEY_CTX_free(ctx);
        OSSL_PARAM_free(params);
        OSSL_PARAM_BLD_free(bld);
    }
    BN_clear_free(bn);
    if (!ok) { EVP_PKEY_free(pkey); return std::nullopt; }
    TestOnlyP256Signer s;
    s.impl_ = std::make_shared<Impl>();
    s.impl_->pkey = pkey;
    s.pub_ = pt;
    return s;
}

std::optional<Sig64> TestOnlyP256Signer::sign_prehashed(const Hash32& digest) const {
    if (!impl_) return std::nullopt;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, impl_->pkey, nullptr);
    std::size_t len = 0;
    Bytes der;
    bool ok = ctx && EVP_PKEY_sign_init(ctx) == 1 &&
              EVP_PKEY_sign(ctx, nullptr, &len, digest.data(), digest.size()) == 1;
    if (ok) {
        der.resize(len);
        ok = EVP_PKEY_sign(ctx, der.data(), &len, digest.data(), digest.size()) == 1;
        der.resize(len);
    }
    EVP_PKEY_CTX_free(ctx);
    if (!ok) return std::nullopt;
    const unsigned char* p = der.data();
    ECDSA_SIG* s = d2i_ECDSA_SIG(nullptr, &p, static_cast<long>(der.size()));
    if (!s) return std::nullopt;
    const BIGNUM* r = nullptr;
    const BIGNUM* sv = nullptr;
    ECDSA_SIG_get0(s, &r, &sv);
    Sig64 out{};
    ok = BN_bn2binpad(r, out.data(), 32) == 32 && BN_bn2binpad(sv, out.data() + 32, 32) == 32;
    ECDSA_SIG_free(s);
    if (!ok) return std::nullopt;
    if (cmp_be(out.data() + 32, kHalfN) > 0) {   // s := n - s (low-s)
        int borrow = 0;
        for (int i = 31; i >= 0; --i) {
            int v = kN[i] - out[32 + i] - borrow;
            borrow = v < 0;
            out[32 + i] = static_cast<std::uint8_t>(v + (borrow ? 256 : 0));
        }
    }
    return out;
}

std::string to_hex(const std::uint8_t* p, std::size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s(2 * n, '0');
    for (std::size_t i = 0; i < n; ++i) { s[2 * i] = d[p[i] >> 4]; s[2 * i + 1] = d[p[i] & 15]; }
    return s;
}

bool from_hex(std::string_view hex, std::uint8_t* out, std::size_t out_len) {
    if (hex.size() != 2 * out_len) return false;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i < out_len; ++i) {
        const int hi = nib(hex[2 * i]), lo = nib(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<std::uint8_t>(hi << 4 | lo);
    }
    return true;
}

}  // namespace ct01::audit::crypto
