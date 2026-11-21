add_library(audit_doctest INTERFACE)
target_include_directories(audit_doctest SYSTEM INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/third_party/doctest)

add_executable(gen_writer_chains diff/gen_writer_chains.cpp)
target_link_libraries(gen_writer_chains PRIVATE audit_chain)

# Differential vs the independent naive oracle (needs a python3 with `cryptography`).
find_program(AUDIT_ORACLE_PYTHON NAMES python3 PATHS /usr/bin NO_DEFAULT_PATH)
if(AUDIT_ORACLE_PYTHON)
  execute_process(COMMAND ${AUDIT_ORACLE_PYTHON} -c "import cryptography" RESULT_VARIABLE _crypto_rc OUTPUT_QUIET ERROR_QUIET)
endif()
set(AUDIT_HARNESS ${CMAKE_CURRENT_SOURCE_DIR}/../../audit/harness)
if(AUDIT_ORACLE_PYTHON AND _crypto_rc EQUAL 0 AND EXISTS ${AUDIT_HARNESS}/audit_chain_naive_verify.py)
  add_test(NAME oracle_differential
           COMMAND ${AUDIT_ORACLE_PYTHON} -B ${CMAKE_CURRENT_SOURCE_DIR}/diff/oracle_diff.py
                   --verifier $<TARGET_FILE:ct01_audit_verify> --gen $<TARGET_FILE:gen_writer_chains>
                   --harness ${AUDIT_HARNESS} --workdir ${CMAKE_CURRENT_BINARY_DIR}/oracle_diff_work)
else()
  message(STATUS "oracle_differential: skipped (no python3 with cryptography, or no audit/harness)")
endif()

add_executable(audit_unit_tests
  unit/doctest_main.cpp
  unit/test_exit_matrix.cpp
  unit/test_verify_rules.cpp
  unit/test_crypto_layout.cpp
  unit/test_fields_inputs.cpp
  unit/test_writer_json_cli.cpp)
target_include_directories(audit_unit_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/unit)
target_link_libraries(audit_unit_tests PRIVATE audit_chain audit_doctest)
target_compile_definitions(audit_unit_tests PRIVATE AUDIT_CLI_PATH="$<TARGET_FILE:ct01_audit_verify>")
add_dependencies(audit_unit_tests ct01_audit_verify)
add_test(NAME audit_unit_tests COMMAND audit_unit_tests)

# Generated tables vs DESIGN v0.3.4 Appendix A; layout header vs the layout spec.
if(AUDIT_ORACLE_PYTHON)
  add_test(NAME codes_vs_design COMMAND ${AUDIT_ORACLE_PYTHON} -B ${CMAKE_CURRENT_SOURCE_DIR}/tools/gen_codes.py --check)
  add_executable(dump_layout tools/dump_layout.cpp)
  target_link_libraries(dump_layout PRIVATE audit_chain)
  add_test(NAME layout_vs_spec COMMAND ${AUDIT_ORACLE_PYTHON} -B ${CMAKE_CURRENT_SOURCE_DIR}/tools/layout_vs_spec.py
           $<TARGET_FILE:dump_layout> ${CMAKE_CURRENT_SOURCE_DIR}/spec/layout_v0_3_4.log)
endif()

# Fuzz targets (DESIGN 9): record parser + chain verifier. Two front ends each:
#  * <name>_driver: plain main() (fuzz/standalone_driver.cpp), any compiler; replays the seeds READ-ONLY
#    and runs seeded random mutations in memory (never writes files).
#  * <name>: libFuzzer (-fsanitize=fuzzer), clang only, AUDIT_FUZZ=ON. Smoke run in CTest with a scratch
#    corpus dir passed FIRST so new units never land in the committed seeds.
add_executable(make_seeds fuzz/make_seeds.cpp)
target_link_libraries(make_seeds PRIVATE audit_chain)
function(audit_fuzz_target name corpus_name)
  set(corpus ${CMAKE_CURRENT_SOURCE_DIR}/fuzz/corpus/${corpus_name})
  add_executable(${name}_driver fuzz/${name}.cpp fuzz/standalone_driver.cpp)
  target_link_libraries(${name}_driver PRIVATE audit_chain)
  add_test(NAME ${name}_corpus_random
           COMMAND ${name}_driver --random ${AUDIT_FUZZ_DRIVER_ITERATIONS} --seed 20261111 ${corpus})
  if(AUDIT_FUZZ)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
      message(FATAL_ERROR "AUDIT_FUZZ=ON needs clang (libFuzzer); use the clang opt-in in .toolchain/env.sh")
    endif()
    add_executable(${name} fuzz/${name}.cpp)
    target_link_libraries(${name} PRIVATE audit_chain)
    target_compile_options(${name} PRIVATE -fsanitize=fuzzer)
    target_link_options(${name} PRIVATE -fsanitize=fuzzer)
    set(scratch ${CMAKE_CURRENT_BINARY_DIR}/${name}_scratch)
    file(MAKE_DIRECTORY ${scratch})
    add_test(NAME ${name}_libfuzzer_smoke COMMAND ${name} -runs=20000 -seed=1 ${scratch} ${corpus})
  endif()
endfunction()
audit_fuzz_target(fuzz_record_parse record_parse)
audit_fuzz_target(fuzz_chain_verify chain_verify)
