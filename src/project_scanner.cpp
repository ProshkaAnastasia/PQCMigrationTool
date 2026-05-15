#include "pqc/project_scanner.hpp"
#include <fstream>
#include <algorithm>
#include <iostream>
#include <set>

namespace pqc {

std::string file_category_str(FileCategory c){
    switch(c){
    case FileCategory::SOURCE: return "source";
    case FileCategory::HEADER: return "header";
    case FileCategory::BUILD: return "build";
    case FileCategory::CONFIG: return "config";
    case FileCategory::TEST: return "test";
    case FileCategory::DOCUMENTATION: return "documentation";
    case FileCategory::RESOURCE: return "resource";
    case FileCategory::CERTIFICATE: return "certificate";
    default: return "other";
    }
}

bool CppLanguagePlugin::matches(const std::filesystem::path& p) const {
    static const std::set<std::string> ext = {
        ".cpp", ".cxx", ".cc", ".c", ".hpp", ".hxx", ".hh", ".h", ".ipp", ".inl"
    };
    return ext.count(p.extension().string()) > 0;
}


FileCategory CppLanguagePlugin::categorize(const std::filesystem::path& p) const {
    static const std::set<std::string> header_ext = {
        ".hpp", ".hxx", ".hh", ".h", ".ipp", ".inl"
    };

    std::string ext = p.extension().string();
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    if (header_ext.count(ext)) return FileCategory::HEADER;

    std::vector<std::string> parts;
    for (const auto& part : p) {
        std::string s = part.string();
        std::transform(s.begin(), s.end(), s.begin(), ::tolower);
        parts.push_back(s);
    }

    std::string filename = p.filename().string();
    std::transform(filename.begin(), filename.end(), filename.begin(), ::tolower);

    bool in_tests = false;
    bool in_fixtures = false;

    for (const auto& part : parts) {
        if (part == "test" || part == "tests") 
            in_tests = true;
        if (part == "fixture" || part == "fixtures" || part == "samples") 
            in_fixtures = true;
    }

    if (in_tests && in_fixtures) 
        return FileCategory::SOURCE;
    if (filename.find("_test.") != std::string::npos || filename.rfind("test_", 0) == 0)
        return FileCategory::TEST;
    if (in_tests) 
        return FileCategory::TEST;

    return FileCategory::SOURCE;
}

bool CMakeLanguagePlugin::matches(const std::filesystem::path& p) const {
    std::string fn = p.filename().string(); 
    std::string ext = p.extension().string();
    return fn == "CMakeLists.txt" || ext == ".cmake";
}

bool CertFilePlugin::matches(const std::filesystem::path& p) const {
    static const std::set<std::string> ext = {
        ".pem", ".crt", ".cer", ".der", ".p7b", ".p12", ".pfx"
    };
    return ext.count(p.extension().string()) > 0;
}

std::vector<const FileEntry*> ProjectInventory::get_by_category(FileCategory c) const {
    std::vector<const FileEntry*> r;

    for (auto& f : files) {
        if (f.category == c) {
            r.push_back(&f);
        }
    }

    return r;
}

std::vector<const FileEntry*> ProjectInventory::get_source_files() const {
    std::vector<const FileEntry*> r;

    for (auto& f : files) {
        if (f.category == FileCategory::SOURCE || f.category == FileCategory::HEADER) {
            r.push_back(&f);
        }
    }

    return r;
}

nlohmann::json ProjectInventory::to_cbom_metadata() const {
    nlohmann::json j;
    j["project_name"] = project_name;
    j["project_path"] = project_path;
    j["total_files"] = (int)files.size();

    nlohmann::json bc = nlohmann::json::object();
    std::map<std::string, int> cats;

    for (auto& f : files) {
        ++cats[file_category_str(f.category)];
    }

    for (auto& [k, v] : cats) {
        bc[k] = v;
    }

    j["by_category"] = bc;
    j["language_stats"] = language_stats;

    return j;
}

void ProjectInventory::print_summary() const {
    std::cout << "  Project: " << project_name << " (" << project_path << ")\n";

    std::map<std::string, int> cats;
    for (auto& f : files) {
        ++cats[file_category_str(f.category)];
    }

    for (auto& [k, v] : cats) {
        std::cout << "    " << k << ": " << v << "\n";
    }

    std::cout << "  Languages: ";
    for (auto& [l, c] : language_stats) {
        std::cout << l << "(" << c << ") ";
    }
    std::cout << "\n";
}

ProjectScanner::ProjectScanner() {
    plugins_.push_back(std::make_unique<CppLanguagePlugin>());
    plugins_.push_back(std::make_unique<CMakeLanguagePlugin>());
    plugins_.push_back(std::make_unique<CertFilePlugin>());
}

void ProjectScanner::register_plugin(std::unique_ptr<ILanguagePlugin> plugin) {
    plugins_.push_back(std::move(plugin));
}

bool ProjectScanner::should_skip(const std::filesystem::path& p) {
    static const std::set<std::string> skip = {
        ".git", ".svn", "build", "cmake-build-debug", "cmake-build-release",
        "CMakeFiles", "node_modules", "vendor", "third_party", "external"
    };

    for (auto& s : skip) {
        if (p.filename() == s) {
            return true;
        }
    }

    return false;
}

int ProjectScanner::count_lines(const std::filesystem::path& p) {
    std::ifstream f(p);
    int count = 0;
    std::string l;

    while (std::getline(f, l)) {
        ++count;
    }

    return count;
}

ProjectInventory ProjectScanner::scan(const std::string& root_path) const {
    ProjectInventory inv;
    inv.project_path = root_path;
    std::filesystem::path root(root_path);
    inv.project_name = root.filename().string();

    if (inv.project_name.empty() || inv.project_name == ".") {
        inv.project_name = "project";
    }

    std::error_code ec;
    if (!std::filesystem::exists(root, ec)) {
        throw std::runtime_error("Path not found: " + root_path);
    }

    if (std::filesystem::is_regular_file(root, ec)) {
        for (auto& pl : plugins_) {
            if (pl->matches(root)) {
                FileEntry fe;
                fe.path = root;
                fe.category = pl->categorize(root);
                fe.language = pl->language_name();
                fe.size_bytes = std::filesystem::file_size(root, ec);
                fe.line_count = count_lines(root);

                inv.files.push_back(fe);
                ++inv.language_stats[pl->language_name()];
                break;
            }
        }
        return inv;
    }

    auto dir_options = std::filesystem::directory_options::skip_permission_denied;
    for (auto& entry : std::filesystem::recursive_directory_iterator(root, dir_options, ec)) {
        if (entry.is_directory(ec) && should_skip(entry.path())) {
            continue;
        }

        bool skip = false;
        for (auto it = entry.path().begin(); it != entry.path().end() && !skip; ++it) {
            if (should_skip(*it)) {
                skip = true;
            }
        }

        if (skip) {
            continue;
        }

        if (!entry.is_regular_file(ec)) {
            continue;
        }

        for (auto& pl : plugins_) {
            if (pl->matches(entry.path())) {
                FileEntry fe;
                fe.path = entry.path();
                fe.category = pl->categorize(entry.path());
                fe.language = pl->language_name();
                fe.size_bytes = entry.file_size(ec);
                fe.line_count = count_lines(entry.path());

                inv.files.push_back(fe);
                ++inv.language_stats[pl->language_name()];
                break;
            }
        }
    }
    return inv;
}

}
