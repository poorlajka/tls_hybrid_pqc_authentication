
if (${MIRATH_BUILD_TYPE} STREQUAL "opt") 
    set(MIRATH "${CMAKE_CURRENT_SOURCE_DIR}/mirath/Optimized_Implementation/mirath_tcith/avx/mirath_tcith_${MIRATH_SEC_LEVEL}${MIRATH_Q}_${MIRATH_BALANCE}")
elseif (${MIRATH_BUILD_TYPE} STREQUAL "ref")
    set(MIRATH "${CMAKE_CURRENT_SOURCE_DIR}/mirath/Reference_Implementation/mirath_tcith/mirath_tcith_${MIRATH_SEC_LEVEL}${MIRATH_Q}_${MIRATH_BALANCE}")
endif ()

if (${MIRATH_BALANCE} STREQUAL "fast")
    set(BALANCE "f")
elseif (${MIRATH_BALANCE} STREQUAL "short")
    set(BALANCE "s")
endif()

set(MIRATH_OBJECTS 
    ${MIRATH}/sign.o 
    ${MIRATH}/rng.o 
    ${MIRATH}/common/fips202.o 
    ${MIRATH}/common/hash.o 
    ${MIRATH}/common/KeccakHash.o 
    ${MIRATH}/common/KeccakP-1600-opt64.o 
    ${MIRATH}/common/prng.o 
    ${MIRATH}/mirath_ggm_tree.o 
    ${MIRATH}/mirath_keygen.o 
    ${MIRATH}/mirath_matrix_ff.o 
    ${MIRATH}/mirath_parsing.o 
    ${MIRATH}/mirath_sign.o 
    ${MIRATH}/mirath_tcith.o 
    ${MIRATH}/mirath_verify.o
)

add_custom_target(mirath_make
    COMMAND make mirath_${MIRATH_SEC_LEVEL}${MIRATH_Q}_${BALANCE}
    WORKING_DIRECTORY ${MIRATH}
    VERBATIM
)

add_library(mirath_wrapper mirath_wrapper.c)
add_dependencies(mirath_wrapper mirath_make)
target_link_libraries(mirath_wrapper PRIVATE ${MIRATH_OBJECTS})

target_include_directories(mirath_wrapper PRIVATE 
    ${MIRATH} 
    ${MIRATH}/common
    ${MIRATH}/common/rijndael
    ${MIRATH}/parameters
    ${MIRATH}/arith
    ${MIRATH}/arith/q_16
    ${MIRATH}/arith/q_16/mu_short
)

find_package(OpenSSL REQUIRED)
target_include_directories(mirath_wrapper PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(mirath_wrapper PRIVATE OpenSSL::SSL OpenSSL::Crypto)

