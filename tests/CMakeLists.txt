cmake_minimum_required(VERSION 3.16)

# ── Unit tests ────────────────────────────────────────────────────────────────
add_executable(pqc_unit_tests
    unit/test_main.cpp
    unit/test_vuln_database.cpp
    unit/test_project_scanner.cpp
    unit/test_regex_analyzer.cpp
    unit/test_ast_analyzer.cpp
    unit/test_risk_assessor.cpp
    unit/test_metrics.cpp
)
target_include_directories(pqc_unit_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(pqc_unit_tests PRIVATE pqc_core)
target_compile_definitions(pqc_unit_tests PRIVATE
    PQC_TEST_FIXTURES_DIR="${CMAKE_SOURCE_DIR}/tests/fixtures"
    PQC_TEST_DATA_DIR="${CMAKE_SOURCE_DIR}/data")
add_test(NAME unit_tests COMMAND pqc_unit_tests
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

# ── Integration tests ─────────────────────────────────────────────────────────
add_executable(pqc_integration_tests
    integration/test_full_pipeline.cpp)
target_include_directories(pqc_integration_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(pqc_integration_tests PRIVATE pqc_core)
target_compile_definitions(pqc_integration_tests PRIVATE
    PQC_TEST_FIXTURES_DIR="${CMAKE_SOURCE_DIR}/tests/fixtures"
    PQC_TEST_DATA_DIR="${CMAKE_SOURCE_DIR}/data")
add_test(NAME integration_tests COMMAND pqc_integration_tests
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
