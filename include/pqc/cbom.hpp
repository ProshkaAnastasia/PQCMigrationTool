#pragma once
#include <string>
#include <vector>
#include <optional>
#include <nlohmann/json.hpp>
namespace pqc {
enum class CbomAssetType { ALGORITHM, CERTIFICATE, PROTOCOL, RELATED_CRYPTO_MATERIAL };
struct CbomAlgorithmProperties {
    std::string primitive, executionEnvironment = "software", implementationPlatform = "unknown";
    std::optional<std::string> parameterSetIdentifier, cryptoFunctions;
    std::optional<int> classicalSecurityLevel, quantumSecurityLevel;
    nlohmann::json to_json() const;
};
struct CbomComponent {
    std::string bom_ref, type = "cryptographic-asset", name;
    CbomAssetType assetType = CbomAssetType::ALGORITHM;
    CbomAlgorithmProperties algorithmProperties;
    std::string file_path, context_function, library_source, quantum_vulnerability;
    int line_number = 0;
    double risk_score = 0.0;
    nlohmann::json to_json() const;
};
struct Cbom {
    std::string bomFormat = "CycloneDX", specVersion = "1.5", serialNumber, timestamp;
    int version = 1;
    std::vector<CbomComponent> components;
    void add_component(CbomComponent c);
    nlohmann::json to_json() const;
    static Cbom create_new();
};
}  // namespace pqc
