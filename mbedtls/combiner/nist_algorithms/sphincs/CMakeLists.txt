
if (${SPHINCS_BUILD_TYPE} STREQUAL "opt") 
    set(SPHINCS "${CMAKE_CURRENT_SOURCE_DIR}/sphincs/Optimized_Implementation/crypto_sign/sphincs-${SPHINCS_HASH}-${SPHINCS_SEC_LEVEL}${SPHINCS_BALANCE}-${SPHINCS_VARIANT}")
elseif (${SPHINCS_BUILD_TYPE} STREQUAL "ref")
    set(SPHINCS "${CMAKE_CURRENT_SOURCE_DIR}/sphincs/Reference_Implementation/crypto_sign/sphincs-${SPHINCS_HASH}-${SPHINCS_SEC_LEVEL}${SPHINCS_BALANCE}-${SPHINCS_VARIANT}")
endif ()

set(SPHINCS_OBJECTS 
    ${SPHINCS}/address.o
    ${SPHINCS}/rng.o
    ${SPHINCS}/wots.o
    ${SPHINCS}/utils.o
    ${SPHINCS}/fors.o
    ${SPHINCS}/sign.o
    ${SPHINCS}/sha256.o
    ${SPHINCS}/hash_sha256.o
    ${SPHINCS}/thash_sha256_robust.o
    #${SPHINCS}/haraka.o
)


add_custom_target(sphincs_make
    COMMAND make 
    WORKING_DIRECTORY ${SPHINCS}
    VERBATIM
)

add_library(sphincs_wrapper sphincs_wrapper.c)
add_dependencies(sphincs_wrapper sphincs_make)
target_link_libraries(sphincs_wrapper PRIVATE ${SPHINCS_OBJECTS})

target_include_directories(sphincs_wrapper PRIVATE 
    ${SPHINCS}
)

find_package(OpenSSL REQUIRED)
target_include_directories(sphincs_wrapper PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(sphincs_wrapper PRIVATE OpenSSL::SSL OpenSSL::Crypto)

