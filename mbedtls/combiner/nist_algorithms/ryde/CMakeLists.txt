
if (${RYDE_BUILD_TYPE} STREQUAL "opt") 
    set(RYDE "${CMAKE_CURRENT_SOURCE_DIR}/ryde/Optimized_Implementation/ryde${RYDE_SEC_LEVEL}${RYDE_BALANCE}")
elseif (${RYDE_BUILD_TYPE} STREQUAL "ref")
    set(RYDE "${CMAKE_CURRENT_SOURCE_DIR}/ryde/Reference_Implementation/ryde${RYDE_SEC_LEVEL}${RYDE_BALANCE}")
endif ()

set(RYDE_BUILD ${RYDE}/bin/build)


if (${RYDE_SEC_LEVEL} EQUAL 1)
    set(RYDE_OBJECTS 
        ${RYDE_BUILD}/rbc_53_elt.o
        ${RYDE_BUILD}/rbc_53_vec.o
        ${RYDE_BUILD}/rbc_53_vspace.o
        ${RYDE_BUILD}/rbc_53_mat.o
        ${RYDE_BUILD}/rbc_53_mat_fq.o
        ${RYDE_BUILD}/keypair.o
        ${RYDE_BUILD}/signature.o
        ${RYDE_BUILD}/verification.o
        ${RYDE_BUILD}/parsing.o
        ${RYDE_BUILD}/ggm_tree.o
        ${RYDE_BUILD}/sign.o
        ${RYDE_BUILD}/tcith-rijndael.o
        ${RYDE_BUILD}/SimpleFIPS202.o
        ${RYDE_BUILD}/randombytes.o
    )
elseif (${RYDE_SEC_LEVEL} EQUAL 3)
    set(RYDE_OBJECTS 
        ${RYDE_BUILD}/rbc_61_elt.o
        ${RYDE_BUILD}/rbc_61_vec.o
        ${RYDE_BUILD}/rbc_61_vspace.o
        ${RYDE_BUILD}/rbc_61_mat.o
        ${RYDE_BUILD}/rbc_61_mat_fq.o
        ${RYDE_BUILD}/keypair.o
        ${RYDE_BUILD}/signature.o
        ${RYDE_BUILD}/verification.o
        ${RYDE_BUILD}/parsing.o
        ${RYDE_BUILD}/ggm_tree.o
        ${RYDE_BUILD}/sign.o
        ${RYDE_BUILD}/tcith-rijndael.o
        ${RYDE_BUILD}/SimpleFIPS202.o
        ${RYDE_BUILD}/randombytes.o

    )
elseif (${RYDE_SEC_LEVEL} EQUAL 5)
    set(RYDE_OBJECTS 
        ${RYDE_BUILD}/rbc_67_elt.o
        ${RYDE_BUILD}/rbc_67_vec.o
        ${RYDE_BUILD}/rbc_67_vspace.o
        ${RYDE_BUILD}/rbc_67_mat.o
        ${RYDE_BUILD}/rbc_67_mat_fq.o
        ${RYDE_BUILD}/keypair.o
        ${RYDE_BUILD}/signature.o
        ${RYDE_BUILD}/verification.o
        ${RYDE_BUILD}/parsing.o
        ${RYDE_BUILD}/ggm_tree.o
        ${RYDE_BUILD}/sign.o
        ${RYDE_BUILD}/tcith-rijndael.o
        ${RYDE_BUILD}/SimpleFIPS202.o
        ${RYDE_BUILD}/randombytes.o
    )
endif ()

add_custom_target(ryde_make
    COMMAND make ryde${RYDE_SEC_LEVEL}${RYDE_BALANCE}-${RYDE_COMMIT_GEN}-main
    WORKING_DIRECTORY ${RYDE}
    VERBATIM
)

add_library(ryde_wrapper ryde_wrapper.c)
add_dependencies(ryde_wrapper ryde_make)
target_link_libraries(ryde_wrapper PRIVATE ${RYDE_OBJECTS})

target_include_directories(ryde_wrapper PRIVATE 
    ${RYDE}/src
    ${RYDE}/src/rbc-67
    ${RYDE}/src/wrapper
    ${RYDE}/lib/XKCP3:
    ${RYDE}/lib/XKCP/avx2
    ${RYDE}/lib/randombytes
)

find_package(OpenSSL REQUIRED)
target_include_directories(ryde_wrapper PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(ryde_wrapper PRIVATE OpenSSL::SSL OpenSSL::Crypto)

