#pragma once
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <filesystem>
#include <nlohmann/json.hpp>
namespace pqc {

enum class FileCategory {
    SOURCE,
    HEADER,
    BUILD,
    CONFIG,
    TEST,
    DOCUMENTATION,
    RESOURCE,
    CERTIFICATE,
    OTHER
};

std::string file_category_str(FileCategory c);

struct FileEntry {
    std::filesystem::path path;
    FileCategory category = FileCategory::OTHER;
    std::string language;
    size_t size_bytes = 0;
    int line_count = 0;
};

struct ProjectInventory {
    std::string project_path;
    std::string project_name;
    std::vector<FileEntry> files;
    std::map<std::string, int> language_stats;

    std::vector<const FileEntry*> get_by_category(FileCategory c) const;
    std::vector<const FileEntry*> get_source_files() const;
    nlohmann::json to_cbom_metadata() const;
    void print_summary() const;
};

class ILanguagePlugin {
public:
    virtual ~ILanguagePlugin() = default;
    virtual std::string language_name() const = 0;
    virtual bool matches(const std::filesystem::path& p) const = 0;
    virtual FileCategory categorize(const std::filesystem::path& p) const = 0;
};

class CppLanguagePlugin : public ILanguagePlugin {
public:
    std::string language_name() const override { return "cpp"; }
    bool matches(const std::filesystem::path& p) const override;
    FileCategory categorize(const std::filesystem::path& p) const override;
};

class CMakeLanguagePlugin : public ILanguagePlugin {
public:
    std::string language_name() const override { return "cmake"; }
    bool matches(const std::filesystem::path& p) const override;
    FileCategory categorize(const std::filesystem::path&) const override
    {
        return FileCategory::BUILD;
    }
};

class CertFilePlugin : public ILanguagePlugin {
public:
    std::string language_name() const override { return "x509"; }
    bool matches(const std::filesystem::path& p) const override;
    FileCategory categorize(const std::filesystem::path&) const override
    {
        return FileCategory::CERTIFICATE;
    }
};

class ProjectScanner {
public:
    ProjectScanner();
    void register_plugin(std::unique_ptr<ILanguagePlugin> plugin);
    ProjectInventory scan(const std::string& root_path) const;

private:
    std::vector<std::unique_ptr<ILanguagePlugin>> plugins_;
    static int count_lines(const std::filesystem::path& p);
    static bool should_skip(const std::filesystem::path& p);
};

}  // namespace pqc
