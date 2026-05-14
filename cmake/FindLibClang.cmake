cmake_minimum_required(VERSION 3.16)
find_package(LLVM CONFIG QUIET)
if(LLVM_FOUND)
    message(STATUS "[FindLibClang] LLVM ${LLVM_VERSION} found")
    find_library(LIBCLANG_LIBRARY NAMES clang libclang clang-${LLVM_VERSION_MAJOR}
        HINTS "${LLVM_LIBRARY_DIRS}" "${LLVM_DIR}/../..")
    find_path(LIBCLANG_INCLUDE_DIR NAMES clang-c/Index.h HINTS "${LLVM_INCLUDE_DIRS}")
    if(LIBCLANG_LIBRARY AND LIBCLANG_INCLUDE_DIR)
        set(LibClang_VERSION "${LLVM_VERSION}")
    endif()
endif()
if(NOT LIBCLANG_LIBRARY)
    find_library(LIBCLANG_LIBRARY NAMES clang libclang PATHS
        /usr/lib /usr/lib64 /usr/local/lib
        /usr/lib/llvm-20/lib /usr/lib/llvm-19/lib /usr/lib/llvm-18/lib
        /usr/lib/llvm-17/lib /usr/lib/llvm-16/lib /usr/lib/llvm-15/lib
        /opt/homebrew/opt/llvm/lib /usr/local/opt/llvm/lib)
    find_path(LIBCLANG_INCLUDE_DIR NAMES clang-c/Index.h PATHS
        /usr/include /usr/local/include
        /usr/lib/llvm-20/include /usr/lib/llvm-19/include /usr/lib/llvm-18/include
        /usr/lib/llvm-17/include /usr/lib/llvm-16/include /usr/lib/llvm-15/include
        /opt/homebrew/opt/llvm/include /usr/local/opt/llvm/include)
endif()
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LibClang FOUND_VAR LibClang_FOUND
    REQUIRED_VARS LIBCLANG_LIBRARY LIBCLANG_INCLUDE_DIR)
if(LibClang_FOUND)
    set(LibClang_LIBRARIES "${LIBCLANG_LIBRARY}")
    set(LibClang_INCLUDE_DIRS "${LIBCLANG_INCLUDE_DIR}")
    if(NOT LibClang_VERSION) 
        set(LibClang_VERSION "unknown") 
    endif()
    message(STATUS "[FindLibClang] ${LibClang_LIBRARIES} (v${LibClang_VERSION})")
    mark_as_advanced(LIBCLANG_LIBRARY LIBCLANG_INCLUDE_DIR)
endif()
