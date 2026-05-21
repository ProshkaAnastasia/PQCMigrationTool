#include "protocol.hpp"
#include <sstream>
#include <algorithm>

namespace Proto {

// Экранируем переносы строк в PEM для передачи в одну строку
std::string encodeMultiline(const std::string& s) {
    std::string r = s;
    size_t pos = 0;
    while ((pos = r.find('\n', pos)) != std::string::npos) {
        r.replace(pos, 1, "\\n");
        pos += 2;
    }
    return r;
}

std::string decodeMultiline(const std::string& s) {
    std::string r = s;
    size_t pos = 0;
    while ((pos = r.find("\\n", pos)) != std::string::npos) {
        r.replace(pos, 2, "\n");
        pos += 1;
    }
    return r;
}

std::string getField(const std::string& s, const std::string& key) {
    std::istringstream ss(s);
    std::string line;
    std::string prefix = key + "=";
    while (std::getline(ss, line)) {
        if (line.rfind(prefix, 0) == 0)
            return line.substr(prefix.size());
    }
    return "";
}

// ─── ClientHello ─────────────────────────────────────────────────────────────
std::string serialize(const ClientHello& m) {
    std::ostringstream ss;
    ss << "TYPE=CLIENT_HELLO\n";
    ss << "SIGN_PUBKEY=" << encodeMultiline(m.sign_pubkey_pem) << "\n";
    ss << "VKO_PUBKEY="  << encodeMultiline(m.vko_pubkey_pem)  << "\n";
    ss << "NONCE="       << m.nonce_hex                        << "\n";
    return ss.str();
}

ClientHello parseClientHello(const std::string& s) {
    ClientHello m;
    m.sign_pubkey_pem = decodeMultiline(getField(s, "SIGN_PUBKEY"));
    m.vko_pubkey_pem  = decodeMultiline(getField(s, "VKO_PUBKEY"));
    m.nonce_hex       = getField(s, "NONCE");
    return m;
}

// ─── ServerHello ─────────────────────────────────────────────────────────────
std::string serialize(const ServerHello& m) {
    std::ostringstream ss;
    ss << "TYPE=SERVER_HELLO\n";
    ss << "SIGN_PUBKEY="   << encodeMultiline(m.sign_pubkey_pem)   << "\n";
    ss << "VKO_PUBKEY="    << encodeMultiline(m.vko_pubkey_pem)    << "\n";
    ss << "UKM="           << m.ukm_hex                            << "\n";
    ss << "SERVER_NONCE="  << m.server_nonce_hex                   << "\n";
    ss << "SIGNATURE="     << m.signature_hex                      << "\n";
    return ss.str();
}

ServerHello parseServerHello(const std::string& s) {
    ServerHello m;
    m.sign_pubkey_pem  = decodeMultiline(getField(s, "SIGN_PUBKEY"));
    m.vko_pubkey_pem   = decodeMultiline(getField(s, "VKO_PUBKEY"));
    m.ukm_hex          = getField(s, "UKM");
    m.server_nonce_hex = getField(s, "SERVER_NONCE");
    m.signature_hex    = getField(s, "SIGNATURE");
    return m;
}

// ─── ClientFinish ────────────────────────────────────────────────────────────
std::string serialize(const ClientFinish& m) {
    std::ostringstream ss;
    ss << "TYPE=CLIENT_FINISH\n";
    ss << "SIGNATURE=" << m.client_signature_hex << "\n";
    ss << "IV="        << m.iv_hex               << "\n";
    ss << "CIPHER="    << m.ciphertext_hex        << "\n";
    ss << "HMAC="      << m.hmac_hex              << "\n";
    return ss.str();
}

ClientFinish parseClientFinish(const std::string& s) {
    ClientFinish m;
    m.client_signature_hex = getField(s, "SIGNATURE");
    m.iv_hex               = getField(s, "IV");
    m.ciphertext_hex       = getField(s, "CIPHER");
    m.hmac_hex             = getField(s, "HMAC");
    return m;
}

// ─── ServerAck ───────────────────────────────────────────────────────────────
std::string serialize(const ServerAck& m) {
    std::ostringstream ss;
    ss << "TYPE=SERVER_ACK\n";
    ss << "OK="     << (m.ok ? "1" : "0") << "\n";
    ss << "IV="     << m.iv_hex            << "\n";
    ss << "CIPHER=" << m.ciphertext_hex    << "\n";
    ss << "HMAC="   << m.hmac_hex          << "\n";
    ss << "ERROR="  << m.error_msg         << "\n";
    return ss.str();
}

ServerAck parseServerAck(const std::string& s) {
    ServerAck m;
    m.ok            = getField(s, "OK") == "1";
    m.iv_hex        = getField(s, "IV");
    m.ciphertext_hex= getField(s, "CIPHER");
    m.hmac_hex      = getField(s, "HMAC");
    m.error_msg     = getField(s, "ERROR");
    return m;
}

} // namespace Proto
