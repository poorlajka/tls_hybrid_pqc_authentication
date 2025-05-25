if (${PERK_BUILD_TYPE} STREQUAL "opt") 
    set(PERK "${CMAKE_CURRENT_SOURCE_DIR}/perk/Optimized_Implementation/perk-${PERK_SEC_LEVEL}-${PERK_BALANCE}-${PERK_VARIANT}")
    set(PERK_BUILD ${PERK}/build/src)
    set(PERK_LIB ${PERK}/build/lib)

    set(PERK_OBJECTS 
        ${PERK_BUILD}/arithmetic.o
        ${PERK_BUILD}/common.o
        ${PERK_BUILD}/keygen.o
        ${PERK_BUILD}/parsing.o
        ${PERK_BUILD}/permutation.o
        ${PERK_BUILD}/signature.o
        ${PERK_BUILD}/sign.o
        ${PERK_BUILD}/symmetric.o
        ${PERK_BUILD}/symmetric_times4.o
        ${PERK_BUILD}/theta_tree.o
        ${PERK_BUILD}/verbose.o
        ${PERK_BUILD}/verify.o
        ${PERK_LIB}/cryptocode/crypto_memset.o
        ${PERK_LIB}/XKCP/KeccakSpongetimes4.o
        ${PERK_LIB}/XKCP/KeccakSponge.o
        ${PERK_LIB}/XKCP/KeccakHash.o
        ${PERK_LIB}/XKCP/SimpleFIPS202.o
        ${PERK_LIB}/XKCP/KeccakP-1600-times4-SIMD256.o
        ${PERK_LIB}/XKCP/KeccakHashtimes4.o
        ${PERK_LIB}/randombytes/rng.o
        ${PERK_LIB}/XKCP/KeccakP-1600-AVX2.o
        ${PERK_LIB}/djbsort/sort.o
        ${PERK_LIB}/djbsort/djbsort.o
    )
elseif (${PERK_BUILD_TYPE} STREQUAL "ref")
    set(PERK "${CMAKE_CURRENT_SOURCE_DIR}/perk/Reference_Implementation/perk-${PERK_SEC_LEVEL}-${PERK_BALANCE}-${PERK_VARIANT}")
    set(PERK_BUILD ${PERK}/build/src)
    set(PERK_LIB ${PERK}/build/lib)

    set(PERK_OBJECTS 
        ${PERK_BUILD}/arithmetic.o
        ${PERK_BUILD}/common.o
        ${PERK_BUILD}/keygen.o
        ${PERK_BUILD}/parsing.o
        ${PERK_BUILD}/permutation.o
        ${PERK_BUILD}/signature.o
        ${PERK_BUILD}/sign.o
        ${PERK_BUILD}/symmetric.o
        ${PERK_BUILD}/theta_tree.o
        ${PERK_BUILD}/verbose.o
        ${PERK_BUILD}/verify.o
        ${PERK_LIB}/cryptocode/crypto_memset.o
        ${PERK_LIB}/XKCP/KeccakSpongetimes4.o
        ${PERK_LIB}/XKCP/KeccakSponge.o
        ${PERK_LIB}/XKCP/KeccakHash.o
        ${PERK_LIB}/XKCP/SimpleFIPS202.o
        ${PERK_LIB}/XKCP/KeccakP-1600-opt64.o 
        ${PERK_LIB}/XKCP/KeccakP-1600-times4-on1.o 
        ${PERK_LIB}/XKCP/KeccakHashtimes4.o
        ${PERK_LIB}/randombytes/rng.o
        ${PERK_LIB}/djbsort/sort.o
        ${PERK_LIB}/djbsort/djbsort.o
    )
endif ()

add_custom_target(perk_make
    COMMAND make perk-${PERK_SEC_LEVEL}-${PERK_BALANCE}-${PERK_VARIANT}
    WORKING_DIRECTORY ${PERK}
    VERBATIM
)

add_library(perk_wrapper perk_wrapper.c)
add_dependencies(perk_wrapper perk_make)
target_link_libraries(perk_wrapper PRIVATE ${PERK_OBJECTS})

target_include_directories(perk_wrapper PRIVATE 
    ${PERK}/src
    ${PERK}/lib/cryptocode
    ${PERK}/lib/djbsort
    ${PERK}/lib/randombytes
    ${PERK}/lib/XKCP
)

find_package(OpenSSL REQUIRED)
target_include_directories(perk_wrapper PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(perk_wrapper PRIVATE OpenSSL::SSL OpenSSL::Crypto)

