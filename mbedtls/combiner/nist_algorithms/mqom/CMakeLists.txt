set(MQOM "${CMAKE_CURRENT_SOURCE_DIR}/mqom-v2")

if (${MQOM_BUILD_TYPE} STREQUAL "opt") 
    set(ENV{RIJNDAEL_AES_NI} 1)
    set(ENV{KECCAK_AVX2} 1)
elseif (${MQOM_BUILD_TYPE} STREQUAL "ref")
    set(ENV{FIELDS_REF} 1) 
endif ()

set(MQOM_OBJECTS 
    ${MQOM}/rijndael/rijndael_ref.o
    ${MQOM}/rijndael/rijndael_table.o
    ${MQOM}/rijndael/rijndael_aes_ni.o   
    ${MQOM}/xof.o
    ${MQOM}/prg.o
    ${MQOM}/ggm_tree.o
    ${MQOM}/expand_mq.o
    ${MQOM}/keygen.o
    ${MQOM}/blc.o
    ${MQOM}/piop.o
    ${MQOM}/sign.o
    ${MQOM}/sha3/libhash.a
)

add_custom_target(mqom_make
    COMMAND python3 manage.py env ${MQOM_SEC_LEVEL}_${MQOM_BASE_FIELD}_${MQOM_BALANCE}_${MQOM_VARIANT} && make sign
    WORKING_DIRECTORY ${MQOM}
    VERBATIM
)

add_library(mqom_wrapper mqom_wrapper.c)
add_dependencies(mqom_wrapper mqom_make)
target_link_libraries(mqom_wrapper PRIVATE ${MQOM_OBJECTS})

target_include_directories(mqom_wrapper PRIVATE 
    ${MQOM}
    ${MQOM}/fields
    ${MQOM}/generator
    ${MQOM}/parameters
    ${MQOM}/rijndael
    ${MQOM}/sha3
    ${MQOM}/sha3/avx2
    ${MQOM}/sha3/opt64
    ${MQOM}/sha3/plain32
)

find_package(OpenSSL REQUIRED)
target_include_directories(mqom_wrapper PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(mqom_wrapper PRIVATE OpenSSL::SSL OpenSSL::Crypto)

