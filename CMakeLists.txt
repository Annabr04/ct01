# audit_chain - keyed, checkpointed audit chain for CT-01 (M1: verifier, schema/writer library).
# Separate tree; never builds against /workspace/ct01 or ct01d.
cmake_minimum_required(VERSION 3.16)
project(audit_chain LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(AUDIT_SANITIZE "Build everything with AddressSanitizer + UndefinedBehaviorSanitizer" OFF)
option(AUDIT_FUZZ "Also build libFuzzer targets (needs clang: -fsanitize=fuzzer)" OFF)
set(AUDIT_FUZZ_DRIVER_ITERATIONS 20000 CACHE STRING "Random inputs the standalone fuzz driver runs in CTest")

add_compile_options(-Wall -Wextra -Werror)
if(AUDIT_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -D_GLIBCXX_ASSERTIONS)
  add_link_options(-fsanitize=address,undefined -fno-sanitize-recover=all)
endif()

# OpenSSL 3 (libcrypto only). Pass -DOPENSSL_ROOT_DIR=$CT01_OPENSSL_ROOT at configure time.
find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)
if(OPENSSL_ROOT_DIR)
  set(CMAKE_BUILD_RPATH "${OPENSSL_ROOT_DIR}/lib")
endif()

add_library(audit_chain STATIC
  src/audit_crypto.cpp
  src/audit_result.cpp
  src/audit_record.cpp
  src/audit_inputs.cpp
  src/audit_verify.cpp
  src/audit_json.cpp
  src/audit_writer.cpp)
target_include_directories(audit_chain PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(audit_chain PUBLIC OpenSSL::Crypto)
if(AUDIT_FUZZ)
  target_compile_options(audit_chain PRIVATE -fsanitize=fuzzer-no-link)
endif()

add_executable(ct01_audit_verify tools/ct01_audit_verify.cpp)
target_link_libraries(ct01_audit_verify PRIVATE audit_chain)

enable_testing()
add_subdirectory(tests)
