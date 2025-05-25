
set(DILITHIUM "${CMAKE_CURRENT_SOURCE_DIR}/dilithium/${DILITHIUM_BUILD_TYPE}")

set(DILITHIUM_OBJECTS
    ${DILITHIUM}/consts.o
    ${DILITHIUM}/f1600x4.o
    ${DILITHIUM}/fips202.o
    ${DILITHIUM}/fips202x4.o
    ${DILITHIUM}/invntt.o
    ${DILITHIUM}/ntt.o
    ${DILITHIUM}/packing.o
    ${DILITHIUM}/pointwise.o
    ${DILITHIUM}/poly.o
    ${DILITHIUM}/polyvec.o
    ${DILITHIUM}/randombytes.o
    ${DILITHIUM}/rejsample.o
    ${DILITHIUM}/rounding.o
    ${DILITHIUM}/shuffle.o
    ${DILITHIUM}/sign.o
    ${DILITHIUM}/symmetric-shake.o
)

add_custom_target(dilithium_make
    COMMAND make test/test_dilithium${DILITHIUM_SEC_LEVEL}
    WORKING_DIRECTORY ${DILITHIUM}
    VERBATIM
)

add_library(dilithium_wrapper dilithium_wrapper.c)
add_dependencies(dilithium_wrapper dilithium_make)
target_compile_options(dilithium_wrapper PRIVATE -DDILITHIUM_MODE=${DILITHIUM_SEC_LEVEL})

target_link_libraries(dilithium_wrapper PRIVATE 
    ${DILITHIUM_OBJECTS}
)

target_include_directories(dilithium_wrapper PRIVATE 
    ${DILITHIUM}
)

find_package(OpenSSL REQUIRED)
target_include_directories(dilithium_wrapper PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(dilithium_wrapper PRIVATE OpenSSL::SSL OpenSSL::Crypto)
