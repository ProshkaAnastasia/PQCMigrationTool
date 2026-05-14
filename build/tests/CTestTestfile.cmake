# CMake generated Testfile for 
# Source directory: /Users/anastasiapronina/Downloads/pqc-migration-tool-v2/tests
# Build directory: /Users/anastasiapronina/Downloads/pqc-migration-tool-v2/build/tests
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(unit_tests "/Users/anastasiapronina/Downloads/pqc-migration-tool-v2/build/tests/pqc_unit_tests")
set_tests_properties(unit_tests PROPERTIES  WORKING_DIRECTORY "/Users/anastasiapronina/Downloads/pqc-migration-tool-v2" _BACKTRACE_TRIPLES "/Users/anastasiapronina/Downloads/pqc-migration-tool-v2/tests/CMakeLists.txt;19;add_test;/Users/anastasiapronina/Downloads/pqc-migration-tool-v2/tests/CMakeLists.txt;0;")
add_test(integration_tests "/Users/anastasiapronina/Downloads/pqc-migration-tool-v2/build/tests/pqc_integration_tests")
set_tests_properties(integration_tests PROPERTIES  WORKING_DIRECTORY "/Users/anastasiapronina/Downloads/pqc-migration-tool-v2" _BACKTRACE_TRIPLES "/Users/anastasiapronina/Downloads/pqc-migration-tool-v2/tests/CMakeLists.txt;31;add_test;/Users/anastasiapronina/Downloads/pqc-migration-tool-v2/tests/CMakeLists.txt;0;")
