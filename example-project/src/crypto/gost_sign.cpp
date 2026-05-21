// ─────────────────────────────────────────────────────────────────────────────
// ГОСТ Р 34.10-2012 — ЭЦП на эллиптических кривых (через OpenSSL EC)
//
// Алгоритм:
//   Подписание: s = (r·d + k·e) mod n, где e = h(m) mod n, C = k·G
//   Проверка:   v = e⁻¹ mod n, точки z₁ = v·s·G, z₂ = v·r·Q, R = z₁+z₂
//
// Параметры кривых (ТК 26, RFC 7836):
//   256-A: p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97
//   512-A: p = 0x4531ACD1FE0023C7550D267B6B2FEE80922B14B2FFB90F04D4EB7C09B5D2D15
//          DA82F2D7ECB1DBAC719905C5EECC423F1D86E25EDBE23C595D644AAF187E6F8
//
// Примечание: OpenSSL 3.x поддерживает эти кривые через EVP_PKEY с
//   параметром NID или через EC_GROUP_new_curve_GFp с явными параметрами.
// ─────────────────────────────────────────────────────────────────────────────
#include "crypto/gost_sign.hpp"
#include "crypto/streebog.hpp"
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <stdexcept>
#include <cstring>

namespace gost {

// ── Параметры кривых TC26 (RFC 7836) ─────────────────────────────────────────

static const CurveParams CURVE_PARAMS[] = {
    {
        "id-tc26-gost-3410-2012-256-paramSetA",
        "1.2.643.7.1.2.1.1.1",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97",
        "C2173F1513981673AF4892C23035A27CE25E2013BF95AA33B22C656F277E7335",
        "295F9BAE7428ED9CCC20E7C359A9D41A22FCCD9108E17BF7BA9337A6F8AE9513",
        "91E38443A5E82C0D880923425712B2BB658B9196932E02C78B2582FE742DAA28",
        "32879423AB1A0375895786C4BB46E9565FDE0B5344766740AF268ADB32322E5C",
        "400000000000000000000000000000000FD8CDDFC87B6635C115AF556C360C67",
        256,
    },
    {
        "id-tc26-gost-3410-2012-512-paramSetA",
        "1.2.643.7.1.2.1.2.1",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC4",
        "E8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879BD081CFD0B6265EE3CB090F30D27614CB4574010DA90DD862EF9D4EBEE4761503190785A71C760",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003",
        "7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA15E74A9031671484F0B4EB8E6B6149E1D8FD3E5F0",
        512,
    },
    {
        "id-tc26-gost-3410-2012-512-paramSetB",
        "1.2.643.7.1.2.1.2.2",
        "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006F",
        "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006C",
        "687D1B459DC841457E3E06CF6F5E2517B97C7D614AF138BCBF85DC806C4B289F3E965D2DB1416D217F8B276FAD1AB69C50F78BEE1FA3106EFB8CCBC7C5140116",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002",
        "1A8F7EDA389B094C2C071E3647A8940F3C123B697578C213BE6DD9E6C8EC7335DCB228FD1EDF4A39152CBCAAF8C0398828041055F94CEEEC7E21340780FE41BD",
        "800000000000000000000000000000000000000000000000000000000000000149A1EC142565A545ACFDB77BD9D40CFA8B996712101BEA0EC6346C54374F25BD",
        512,
    },
    {
        "id-GostR3410-2001-CryptoPro-A-ParamSet",
        "1.2.643.2.2.35.1",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94",
        "A6",
        "0000000000000000000000000000000000000000000000000000000000000001",
        "8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893",
        256,
    },
    {
        "id-GostR3410-2001-TestParamSet",
        "1.2.643.2.2.35.0",
        "8000000000000000000000000000000000000000000000000000000000000431",
        "0000000000000000000000000000000000000000000000000000000000000007",
        "5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E",
        "0000000000000000000000000000000000000000000000000000000000000002",
        "08E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBAEA0B812F4",
        "8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3",
        256,
    },
};

const CurveParams& get_curve_params(GostCurve curve) {
    return CURVE_PARAMS[static_cast<int>(curve)];
}

// ── Создание EC_GROUP по параметрам кривой ────────────────────────────────────

static EC_GROUP* make_ec_group(const CurveParams& cp) {
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM *p = NULL, *a = NULL, *b = NULL, *gx = NULL, *gy = NULL, *n = NULL;

    BN_hex2bn(&p,  cp.p.c_str());
    BN_hex2bn(&a,  cp.a.c_str());
    BN_hex2bn(&b,  cp.b.c_str());
    BN_hex2bn(&gx, cp.gx.c_str());
    BN_hex2bn(&gy, cp.gy.c_str());
    BN_hex2bn(&n,  cp.n.c_str());

    EC_GROUP* group = EC_GROUP_new_curve_GFp(p, a, b, ctx);
    if (!group) goto cleanup;

    {
        EC_POINT* G = EC_POINT_new(group);
        EC_POINT_set_affine_coordinates(group, G, gx, gy, ctx);
        EC_GROUP_set_generator(group, G, n, BN_value_one());
        EC_POINT_free(G);
    }

cleanup:
    BN_free(p); BN_free(a); BN_free(b);
    BN_free(gx); BN_free(gy); BN_free(n);
    BN_CTX_free(ctx);
    return group;
}

// ── GostKeyPair::Impl ─────────────────────────────────────────────────────────

struct GostKeyPair::Impl {
    EC_KEY*    ec_key  = nullptr;
    EC_GROUP*  group   = nullptr;
    GostCurve  curve;

    Impl(GostCurve c) : curve(c) {
        const CurveParams& cp = get_curve_params(c);
        group = make_ec_group(cp);
        if (!group) throw std::runtime_error("Не удалось создать EC group для ГОСТ Р 34.10-2012");
        ec_key = EC_KEY_new();
        EC_KEY_set_group(ec_key, group);
    }
    ~Impl() {
        if (ec_key) EC_KEY_free(ec_key);
        if (group)  EC_GROUP_free(group);
    }
};

// ── GostKeyPair ───────────────────────────────────────────────────────────────

GostKeyPair::GostKeyPair(std::unique_ptr<Impl> p) : impl_(std::move(p)) {}
GostKeyPair::~GostKeyPair() = default;
GostKeyPair::GostKeyPair(GostKeyPair&&) noexcept = default;
GostKeyPair& GostKeyPair::operator=(GostKeyPair&&) noexcept = default;

GostKeyPair GostKeyPair::generate(GostCurve curve) {
    auto impl = std::make_unique<Impl>(curve);
    // EC_KEY_generate_key — генерирует пару ключей (закрытый + открытый)
    if (!EC_KEY_generate_key(impl->ec_key))
        throw std::runtime_error("EC_KEY_generate_key failed для ГОСТ Р 34.10-2012");
    return GostKeyPair(std::move(impl));
}

GostKeyPair GostKeyPair::from_private_der(const std::vector<uint8_t>& der, GostCurve curve) {
    auto impl = std::make_unique<Impl>(curve);
    const unsigned char* p = der.data();
    EC_KEY* loaded = d2i_ECPrivateKey(nullptr, &p, (long)der.size());
    if (!loaded) throw std::runtime_error("from_private_der: не удалось разобрать DER ключ");
    EC_KEY_free(impl->ec_key);
    impl->ec_key = loaded;
    EC_KEY_set_group(impl->ec_key, impl->group);
    if (!EC_KEY_get0_public_key(impl->ec_key)) {
        EC_POINT* pub = EC_POINT_new(impl->group);
        EC_POINT_mul(impl->group, pub,
                     EC_KEY_get0_private_key(impl->ec_key), nullptr, nullptr, nullptr);
        EC_KEY_set_public_key(impl->ec_key, pub);
        EC_POINT_free(pub);
    }
    return GostKeyPair(std::move(impl));
}

GostCurve GostKeyPair::curve() const { return impl_->curve; }

std::vector<uint8_t> GostKeyPair::private_key_der() const {
    unsigned char* buf = nullptr;
    int len = i2d_ECPrivateKey(impl_->ec_key, &buf);
    if (len < 0) return {};
    std::vector<uint8_t> out(buf, buf + len);
    OPENSSL_free(buf);
    return out;
}

std::vector<uint8_t> GostKeyPair::public_key_der() const {
    unsigned char* buf = nullptr;
    int len = i2o_ECPublicKey(impl_->ec_key, &buf);
    if (len < 0) return {};
    std::vector<uint8_t> out(buf, buf + len);
    OPENSSL_free(buf);
    return out;
}

std::string GostKeyPair::private_key_pem() const {
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_ECPrivateKey(bio, impl_->ec_key, nullptr, nullptr, 0, nullptr, nullptr);
    BUF_MEM* bptr;
    BIO_get_mem_ptr(bio, &bptr);
    std::string pem(bptr->data, bptr->length);
    BIO_free(bio);
    return pem;
}

std::string GostKeyPair::public_key_pem() const {
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_EC_PUBKEY(bio, impl_->ec_key);
    BUF_MEM* bptr;
    BIO_get_mem_ptr(bio, &bptr);
    std::string pem(bptr->data, bptr->length);
    BIO_free(bio);
    return pem;
}

const std::vector<uint8_t>& GostKeyPair::private_key_raw() const {
    static std::vector<uint8_t> buf;
    const BIGNUM* d = EC_KEY_get0_private_key(impl_->ec_key);
    buf.resize(BN_num_bytes(d));
    BN_bn2bin(d, buf.data());
    return buf;
}

// ── GostSigner::Impl ──────────────────────────────────────────────────────────

struct GostSigner::Impl {
    EC_KEY*   ec_key  = nullptr;
    EC_GROUP* group   = nullptr;
    GostCurve curve;

    explicit Impl(const GostKeyPair& kp) : curve(kp.curve()) {
        const CurveParams& cp = get_curve_params(curve);
        group = make_ec_group(cp);
        auto priv_der = kp.private_key_der();
        const unsigned char* p = priv_der.data();
        ec_key = d2i_ECPrivateKey(nullptr, &p, (long)priv_der.size());
        if (!ec_key) throw std::runtime_error("GostSigner: не удалось загрузить закрытый ключ");
        EC_KEY_set_group(ec_key, group);
    }

    ~Impl() {
        if (ec_key) EC_KEY_free(ec_key);
        if (group)  EC_GROUP_free(group);
    }
};

GostSigner::GostSigner(const GostKeyPair& kp)
    : impl_(std::make_unique<Impl>(kp)) {}
GostSigner::~GostSigner() = default;

std::vector<uint8_t> GostSigner::sign(const uint8_t* data, size_t len) const {
    // Хэшируем Стрибогом-256 (для 256-бит кривых)
    Digest256 h = streebog256(data, len);
    return sign_hash(std::vector<uint8_t>(h.begin(), h.end()));
}

std::vector<uint8_t> GostSigner::sign(const std::vector<uint8_t>& data) const {
    return sign(data.data(), data.size());
}

std::vector<uint8_t> GostSigner::sign_hash(const std::vector<uint8_t>& hash) const {
    // ECDSA_sign использует DER-кодированный (r, s)
    // ГОСТ Р 34.10-2012 определяет raw (r || s)
    ECDSA_SIG* sig = ECDSA_do_sign(hash.data(), (int)hash.size(), impl_->ec_key);
    if (!sig) throw std::runtime_error("ECDSA_do_sign/gost_ec_sign failed");

    const BIGNUM* r;
    const BIGNUM* s;
    ECDSA_SIG_get0(sig, &r, &s);

    // Сериализуем в формат ГОСТ: r || s, каждый по 32 байта (для 256-бит)
    const size_t comp_len = 32;
    std::vector<uint8_t> signature(2 * comp_len, 0);
    BN_bn2binpad(r, signature.data(),            comp_len);
    BN_bn2binpad(s, signature.data() + comp_len, comp_len);
    ECDSA_SIG_free(sig);
    return signature;
}

// ── GostVerifier::Impl ────────────────────────────────────────────────────────

struct GostVerifier::Impl {
    EC_KEY*   ec_key;
    EC_GROUP* group;
    GostCurve curve;

    Impl(const std::vector<uint8_t>& pub_der, GostCurve c) : curve(c) {
        const CurveParams& cp = get_curve_params(c);
        group = make_ec_group(cp);
        ec_key = EC_KEY_new();
        EC_KEY_set_group(ec_key, group);
        const unsigned char* p = pub_der.data();
        o2i_ECPublicKey(&ec_key, &p, pub_der.size());
    }
    Impl(const GostKeyPair& kp) : curve(kp.curve()) {
        const CurveParams& cp = get_curve_params(curve);
        group = make_ec_group(cp);
        ec_key = EC_KEY_new();
        EC_KEY_set_group(ec_key, group);
        auto pub_der = kp.public_key_der();
        const unsigned char* p = pub_der.data();
        o2i_ECPublicKey(&ec_key, &p, (long)pub_der.size());
    }
    ~Impl() {
        if (ec_key) EC_KEY_free(ec_key);
        if (group)  EC_GROUP_free(group);
    }
};

GostVerifier::GostVerifier(const std::vector<uint8_t>& pub_der, GostCurve curve)
    : impl_(std::make_unique<Impl>(pub_der, curve)) {}
GostVerifier::GostVerifier(const GostKeyPair& kp)
    : impl_(std::make_unique<Impl>(kp)) {}
GostVerifier::~GostVerifier() = default;

bool GostVerifier::verify(const uint8_t* data, size_t data_len,
                           const std::vector<uint8_t>& signature) const {
    Digest256 h = streebog256(data, data_len);
    if (signature.size() < 64) return false;
    const size_t comp_len = 32;
    ECDSA_SIG* sig = ECDSA_SIG_new();
    BIGNUM* r = BN_bin2bn(signature.data(),            comp_len, nullptr);
    BIGNUM* s = BN_bin2bn(signature.data() + comp_len, comp_len, nullptr);
    ECDSA_SIG_set0(sig, r, s);
    int ok = ECDSA_do_verify(h.data(), (int)h.size(), sig, impl_->ec_key);
    ECDSA_SIG_free(sig);
    return ok == 1;
}

bool GostVerifier::verify(const std::vector<uint8_t>& data,
                           const std::vector<uint8_t>& signature) const {
    return verify(data.data(), data.size(), signature);
}

} // namespace gost