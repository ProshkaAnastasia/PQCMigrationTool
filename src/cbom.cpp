#include "pqc/cbom.hpp"
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <random>
namespace pqc {
static std::string make_uuid()
{
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist;
    uint64_t a = dist(gen), b = dist(gen);
    a = (a & 0xFFFFFFFFFFFF0FFFULL) | 0x0000000000004000ULL;
    b = (b & 0x3FFFFFFFFFFFFFFFULL) | 0x8000000000000000ULL;
    std::ostringstream oss;
    oss << std::hex << std::setfill('0') << std::setw(8) << (a >> 32) << "-" << std::setw(4)
        << ((a >> 16) & 0xFFFF) << "-" << std::setw(4) << (a & 0xFFFF) << "-" << std::setw(4)
        << (b >> 48) << "-" << std::setw(12) << (b & 0x0000FFFFFFFFFFFFULL);
    return oss.str();
}
static std::string now_iso8601()
{
    auto t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::ostringstream o;
    o << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%SZ");
    return o.str();
}
nlohmann::json CbomAlgorithmProperties::to_json() const
{
    nlohmann::json j;
    j["primitive"] = primitive;
    if (parameterSetIdentifier)
        j["parameterSetIdentifier"] = *parameterSetIdentifier;
    if (cryptoFunctions)
        j["cryptoFunctions"] = *cryptoFunctions;
    if (classicalSecurityLevel)
        j["classicalSecurityLevel"] = *classicalSecurityLevel;
    if (quantumSecurityLevel)
        j["quantumSecurityLevel"] = *quantumSecurityLevel;
    j["executionEnvironment"] = executionEnvironment;
    j["implementationPlatform"] = implementationPlatform;
    return j;
}
nlohmann::json CbomComponent::to_json() const
{
    nlohmann::json j;
    j["bom-ref"] = bom_ref;
    j["type"] = type;
    j["name"] = name;
    nlohmann::json cp;
    switch (assetType) {
        case CbomAssetType::ALGORITHM:
            cp["assetType"] = "algorithm";
            break;
        case CbomAssetType::CERTIFICATE:
            cp["assetType"] = "certificate";
            break;
        case CbomAssetType::PROTOCOL:
            cp["assetType"] = "protocol";
            break;
        case CbomAssetType::RELATED_CRYPTO_MATERIAL:
            cp["assetType"] = "related-crypto-material";
            break;
    }
    cp["algorithmProperties"] = algorithmProperties.to_json();
    j["cryptoProperties"] = cp;
    j["x-pqc-source"] = {{"file_path", file_path},
                         {"line_number", line_number},
                         {"context_function", context_function},
                         {"library_source", library_source},
                         {"quantum_vulnerability", quantum_vulnerability},
                         {"risk_score", risk_score}};
    return j;
}
void Cbom::add_component(CbomComponent c)
{
    components.push_back(std::move(c));
}
nlohmann::json Cbom::to_json() const
{
    nlohmann::json j;
    j["bomFormat"] = bomFormat;
    j["specVersion"] = specVersion;
    j["serialNumber"] = "urn:uuid:" + serialNumber;
    j["version"] = version;
    j["metadata"] = {{"timestamp", timestamp}};
    nlohmann::json comp = nlohmann::json::array();
    for (auto& c : components) comp.push_back(c.to_json());
    j["components"] = comp;
    return j;
}
Cbom Cbom::create_new()
{
    Cbom c;
    c.serialNumber = make_uuid();
    c.timestamp = now_iso8601();
    return c;
}
}  // namespace pqc
