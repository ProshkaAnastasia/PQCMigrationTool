#pragma once
// Внутренний заголовок: определение Certificate::Impl для PKI-модулей.
// НЕ включать из публичных заголовков.
#include "pki/cert_manager.hpp"
#include <openssl/x509.h>

namespace gost { namespace pki {

struct Certificate::Impl {
    X509* cert;
    explicit Impl(X509* c) : cert(c) {}
    ~Impl() { if (cert) X509_free(cert); }
};

}} // namespace gost::pki