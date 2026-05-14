cmake_minimum_required(VERSION 3.16)
project(pqc-migration-tool VERSION 2.0.0 LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
option(PQC_BUILD_TESTS "Build unit and integration tests" ON)
option(PQC_REQUIRE_LIBCLANG "Fail if libclang not found" OFF)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
    add_compile_options(-Wall -Wextra -Wpedantic -O2)
elseif(MSVC) 
    add_compile_options(/W4 /O2 /utf-8) 
endif()

include(FetchContent)
FetchContent_Declare(nlohmann_json GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.11.3 GIT_SHALLOW TRUE)
FetchContent_MakeAvailable(nlohmann_json)

find_package(OpenSSL REQUIRED)
message(STATUS "OpenSSL: ${OPENSSL_VERSION}")

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
find_package(LibClang QUIET)
if(LibClang_FOUND)
    message(STATUS "libclang: v${LibClang_VERSION} @ ${LibClang_LIBRARIES}")
    set(PQC_LIBCLANG_AVAILABLE TRUE)
elseif(PQC_REQUIRE_LIBCLANG)
    message(FATAL_ERROR "libclang not found. Install: apt install libclang-dev")
else()
    message(WARNING "libclang NOT found. AST mode uses token-based fallback.\n"
        "  Debian/Ubuntu: sudo apt install libclang-dev\n"
        "  macOS: brew install llvm\n"
        "  Windows: winget install LLVM.LLVM")
    set(PQC_LIBCLANG_AVAILABLE FALSE)
endif()

set(PQC_CORE_SOURCES src/config.cpp src/project_scanner.cpp src/cbom.cpp
    src/vuln_database.cpp src/regex_analyzer.cpp src/token_analyzer.cpp
    src/ast_analyzer.cpp src/cert_analyzer.cpp src/risk_assessor.cpp
    src/report_generator.cpp src/metrics.cpp)
add_library(pqc_core STATIC ${PQC_CORE_SOURCES})
target_include_directories(pqc_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include ${OPENSSL_INCLUDE_DIR})
target_link_libraries(pqc_core PUBLIC nlohmann_json::nlohmann_json OpenSSL::SSL OpenSSL::Crypto)
if(UNIX AND NOT APPLE) 
    target_link_libraries(pqc_core PUBLIC pthread dl) 
endif()
if(PQC_LIBCLANG_AVAILABLE)
    target_compile_definitions(pqc_core PUBLIC PQC_HAS_LIBCLANG)
    target_include_directories(pqc_core PUBLIC ${LibClang_INCLUDE_DIRS})
    target_link_libraries(pqc_core PUBLIC ${LibClang_LIBRARIES})
endif()
target_compile_definitions(pqc_core PUBLIC
    PQC_OPENSSL_INCLUDE_DIR="${OPENSSL_INCLUDE_DIR}"
)

if(APPLE)
  execute_process(
    COMMAND xcrun --sdk macosx --show-sdk-path
    OUTPUT_VARIABLE PQC_MACOS_SDKROOT
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
  if(PQC_MACOS_SDKROOT)
    target_compile_definitions(pqc_core PUBLIC
      PQC_MACOS_SDKROOT="${PQC_MACOS_SDKROOT}"
    )
  endif()
endif()

add_executable(pqc-migration-tool src/main.cpp)
target_link_libraries(pqc-migration-tool PRIVATE pqc_core)
add_custom_command(TARGET pqc-migration-tool POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        "${CMAKE_SOURCE_DIR}/data" "$<TARGET_FILE_DIR:pqc-migration-tool>/data"
    COMMENT "Copying vulnerability database...")
install(TARGETS pqc-migration-tool DESTINATION bin)
install(DIRECTORY data/ DESTINATION share/pqc-migration-tool/data)

if(PQC_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

message(STATUS "=== pqc-migration-tool ${PROJECT_VERSION} ===")
message(STATUS "  libclang: ${PQC_LIBCLANG_AVAILABLE} (${LibClang_VERSION})")
message(STATUS "  OpenSSL : ${OPENSSL_VERSION}")
