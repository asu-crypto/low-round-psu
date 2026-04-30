cmake_minimum_required(VERSION 3.10)

set(CMAKE_VERBOSE_MAKEFILE ON)
set (CMAKE_CXX_STANDARD 23)

set(CMAKE_CXX_COMPILER g++-14)
set(CMAKE_C_COMPILER gcc-14)

project(low-round-psu)

include(CheckIPOSupported)
check_ipo_supported(RESULT supported OUTPUT error)

if(NOT DEFINED VOLEPSI_INSTALL_PATH)
  set(VOLEPSI_INSTALL_PATH "${CMAKE_SOURCE_DIR}/../volepsi")
endif()

#if(NOT DEFINED CRYPTO_TOOLS_INSTALL_PATH)
#  set(CRYPTO_TOOLS_INSTALL_PATH "${CMAKE_SOURCE_DIR}/../cryptoTools")
#endif()

if(NOT DEFINED CATCH2_INSTALL_PATH)
  set(CATCH2_INSTALL_PATH "${CMAKE_SOURCE_DIR}/../catch2")
endif()

set (CMAKE_PREFIX_PATH "${VOLEPSI_INSTALL_PATH};${CATCH2_INSTALL_PATH}")

find_package(Catch2 3 REQUIRED)
find_package(volePSI REQUIRED HINTS "../volepsi")
#find_package(cryptoTools REQUIRED)
#find_package(coproto REQUIRED)
find_path(GMP_INCLUDE_DIR gmp.h)
find_library(GMP_LIBRARIES gmp)
find_library(GMPXX_LIBRARIES gmpxx)

# Add OpenSSL support for modular exponentiation benchmarks
find_package(OpenSSL REQUIRED)

if(NOT GMP_INCLUDE_DIR OR NOT GMP_LIBRARIES)
    message(FATAL_ERROR "Could not find GMP library")
endif()



set(BUILD_PROFILING_EXECUTABLES OFF)

# GCC CXX_FLAGS
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native -ftree-vectorize -fopt-info-vec-optimized")

# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native -ftree-vectorize -fopt-info-vec-optimized")

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
  add_compile_options(-fsanitize=address)
  add_link_options(-fsanitize=address)
endif()

if (CMAKE_BUILD_TYPE STREQUAL "Release")
  add_compile_options(-O3 -Wall -Wextra -Wpedantic)
endif()

if (CMAKE_BUILD_TYPE STREQUAL "Profile")
  add_compile_options(-O3)
  add_compile_options(-pg)
  add_compile_options(-ftree-vectorizer-verbose=6)
  add_link_options(-pg)
  set(BUILD_PROFILING_EXECUTABLES ON)
  set(CMAKE_VERBOSE_MAKEFILE ON)
endif()

message(CMAKE_SOURCE_DIR="${CMAKE_SOURCE_DIR}")

set_source_files_properties(${CMAKE_SOURCE_DIR}/extc_mod_op_utils.c
    PROPERTIES
    LANGUAGE C
    COMPILE_FLAGS "-std=c23 -O3 -march=native -ftree-vectorize -ffast-math -finline-functions -funroll-loops -flto"
)

add_library(iblt_interface STATIC IMPORTED)
set_target_properties(iblt_interface PROPERTIES
    IMPORTED_LOCATION "${CMAKE_SOURCE_DIR}/clang-src/build/libiblt_interface.a"
    INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/clang-src"
    INTERFACE_COMPILE_DEFINITIONS "USE_C_INTERFACE"
)

set(HEADERS
  ${CMAKE_SOURCE_DIR}/utils.hpp
  ${CMAKE_SOURCE_DIR}/rand.hpp
  ${CMAKE_SOURCE_DIR}/paillier.hpp
  ${CMAKE_SOURCE_DIR}/ss.hpp
  ${CMAKE_SOURCE_DIR}/sr_psu.hpp
  ${CMAKE_SOURCE_DIR}/wp_psu.hpp
  ${CMAKE_SOURCE_DIR}/iblt.hpp
  ${CMAKE_SOURCE_DIR}/extc_mod_op_utils.h
  ${CMAKE_SOURCE_DIR}/egpal.hpp
  ${CMAKE_SOURCE_DIR}/ct_iblt.hpp
  ${CMAKE_SOURCE_DIR}/mpz_iblt.hpp
)
set(SOURCES
  ${CMAKE_SOURCE_DIR}/utils.cpp
  ${CMAKE_SOURCE_DIR}/rand.cpp
  ${CMAKE_SOURCE_DIR}/paillier.cpp
  ${CMAKE_SOURCE_DIR}/ss.cpp
  ${CMAKE_SOURCE_DIR}/sr_psu.cpp
  ${CMAKE_SOURCE_DIR}/wp_psu.cpp
  ${CMAKE_SOURCE_DIR}/iblt.cpp
  ${CMAKE_SOURCE_DIR}/extc_mod_op_utils.c
  ${CMAKE_SOURCE_DIR}/egpal.cpp
  ${CMAKE_SOURCE_DIR}/ct_iblt.cpp
  ${CMAKE_SOURCE_DIR}/mpz_iblt.cpp
)

if( supported )
    message(STATUS "IPO / LTO enabled")
else()
    message(SEND_ERROR "IPO / LTO not supported: <${error}>")
endif()

if(BUILD_TESTS)
    set(ALL_TESTS
        utils_test
        rand_test
        paillier_test
        ss_test
        mpz_test
        mod_op_utils_test
        iblt_test
        okvs_test
        wp_psu_test
        sr_psu_test
        egpal_test
        mpz_iblt_test
    )

    set (TEST_SOURCE_PREFIX ${CMAKE_SOURCE_DIR}/tests)

    add_executable(utils_test ${TEST_SOURCE_PREFIX}/utils.test.cpp ${SOURCES})
    add_executable(rand_test ${TEST_SOURCE_PREFIX}/rand.test.cpp ${SOURCES})
    add_executable(paillier_test ${TEST_SOURCE_PREFIX}/paillier.test.cpp ${SOURCES})
    add_executable(ss_test ${TEST_SOURCE_PREFIX}/ss.test.cpp ${SOURCES})
    add_executable(mpz_test ${TEST_SOURCE_PREFIX}/mpz.test.cpp ${SOURCES})
    add_executable(mod_op_utils_test ${TEST_SOURCE_PREFIX}/mod_op_utils.test.cpp ${SOURCES})
    add_executable(iblt_test ${TEST_SOURCE_PREFIX}/iblt.test.cpp ${SOURCES})
    add_executable(okvs_test ${TEST_SOURCE_PREFIX}/okvs.test.cpp ${SOURCES})
    add_executable(wp_psu_test ${TEST_SOURCE_PREFIX}/wp_psu.test.cpp ${SOURCES})
    add_executable(sr_psu_test ${TEST_SOURCE_PREFIX}/sr_psu.test.cpp ${SOURCES})
    add_executable(egpal_test ${TEST_SOURCE_PREFIX}/egpal.test.cpp ${SOURCES})
    add_executable(mpz_iblt_test ${TEST_SOURCE_PREFIX}/mpz_iblt.test.cpp ${SOURCES})

    foreach(target ${ALL_TESTS})
        set_target_properties(${target} PROPERTIES CXX_EXTENSIONS ON)
        target_compile_features(${target} PUBLIC cxx_std_20)
        target_compile_options(${target} PRIVATE ${DEFAULT_COMPILER_OPTIONS_AND_WARNINGS})
        target_link_libraries(${target} PRIVATE Catch2::Catch2WithMain visa::volePSI oc::cryptoTools ${GMP_LIBRARIES} ${GMPXX_LIBRARIES} coproto::coproto iblt_interface)
        target_include_directories(${target} PRIVATE ${GMP_INCLUDE_DIR})
        set_property(TARGET ${target} PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)

        #target_compile_options(${target} PRIVATE ${GMP_CFLAGS_OTHER})

        add_test(NAME ${target} COMMAND ${target})
    endforeach()
endif()

if(BUILD_BENCH)
   set(ALL_BENCHS
        #psu_bench
        #simd_bench
        #ot_reduc
        #iblt_h5_bench
        #bitvector_bench
        #multiaes_bench
        #preprocessing_bench
        wp_psu_bench
        sr_psu_bench
        128bit_bench
        iblt_bench
        okvs_bench
        egpal_bench
        modexp_comparison_bench
    )

    set (BENCH_SOURCE_PREFIX ${CMAKE_SOURCE_DIR}/benchmarks)
    
    add_executable(wp_psu_bench ${BENCH_SOURCE_PREFIX}/wp_psu.bench.cpp ${SOURCES})
    add_executable(sr_psu_bench ${BENCH_SOURCE_PREFIX}/sr_psu.bench.cpp ${SOURCES})
    add_executable(128bit_bench ${BENCH_SOURCE_PREFIX}/128bit.bench.cpp ${SOURCES})
    add_executable(iblt_bench ${BENCH_SOURCE_PREFIX}/iblt.bench.cpp ${SOURCES})
    add_executable(okvs_bench ${BENCH_SOURCE_PREFIX}/okvs.bench.cpp ${SOURCES})
    add_executable(egpal_bench ${BENCH_SOURCE_PREFIX}/egpal.bench.cpp ${SOURCES})
    add_executable(modexp_comparison_bench ${BENCH_SOURCE_PREFIX}/modexp_comparison.cpp ${SOURCES})
    #add_executable(psu_bench ${BENCH_SOURCE_PREFIX}/psu.bench.cpp ${SOURCES})
    #add_executable(ot_reduc ${BENCH_SOURCE_PREFIX}/ot_reduc.bench.cpp ${SOURCES})    
    #add_executable(simd_bench ${BENCH_SOURCE_PREFIX}/simd.bench.cpp ${SOURCES})
    #add_executable(bitvector_bench ${BENCH_SOURCE_PREFIX}/bitvector.bench.cpp ${SOURCES})
    #add_executable(multiaes_bench ${BENCH_SOURCE_PREFIX}/multiaes.bench.cpp ${SOURCES})
    #add_executable(preprocessing_bench ${BENCH_SOURCE_PREFIX}/preprocessing.bench.cpp ${SOURCES})
    #add_executable(iblt_h5_bench ${BENCH_SOURCE_PREFIX}/iblt_h5.bench.cpp ${SOURCES})

    foreach(target ${ALL_BENCHS})
        set_target_properties(${target} PROPERTIES CXX_EXTENSIONS ON)
        target_compile_features(${target} PUBLIC cxx_std_20)
        target_compile_options(${target} PRIVATE ${DEFAULT_COMPILER_OPTIONS_AND_WARNINGS})
        target_link_libraries(${target} PRIVATE Catch2::Catch2WithMain visa::volePSI coproto::coproto ${GMP_LIBRARIES} ${GMPXX_LIBRARIES} iblt_interface)
        set_property(TARGET ${target} PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)

        add_test(NAME ${target} COMMAND ${target})
    endforeach()
    
    # Add OpenSSL linking specifically for the modexp comparison benchmark
    target_link_libraries(modexp_comparison_bench PRIVATE OpenSSL::Crypto)

endif()

if(BUILD_PROFILING_EXECUTABLES)
  set(ALL_PROFILING_EXECUTABLES
    #profiling_psu_with_local_sockets
  )

  set (PROFILING_SOURCE_PREFIX ${CMAKE_SOURCE_DIR}/profiling)

  foreach(target ${ALL_PROFILING_EXECUTABLES})
      add_executable(${target} ${PROFILING_SOURCE_PREFIX}/${target}.cpp ${SOURCES})
      target_link_libraries(${target} visa::volePSI coproto::coproto xxhash unordered_dense::unordered_dense iblt_interface)
      set_property(TARGET ${target} PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
  endforeach()
endif()

#add_executable(psu_main ${CMAKE_SOURCE_DIR}/psu_main.cpp ${SOURCES})
#target_link_libraries(psu_main visa::volePSI coproto::coproto xxhash unordered_dense::unordered_dense)

#target_link_libraries(opt_iblt_exp visa::volePSI)
#if (CMAKE_BUILD_TYPE STREQUAL "Debug")
  #target_compile_definitions(opt_iblt_exp_h4 PRIVATE DEBUG_MODE)
  #target_compile_definitions(opt_iblt_exp_h5 PRIVATE DEBUG_MODE)
  #target_compile_definitions(pround_exps_h5 PRIVATE DEBUG_MODE)
  #target_compile_definitions(trypeel_main PRIVATE DEBUG_MODE)
  #target_compile_definitions(main_iblt_h5 PRIVATE DEBUG_MODE)
#endif()