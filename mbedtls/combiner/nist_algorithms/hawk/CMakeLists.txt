set(HAWK ${CMAKE_CURRENT_SOURCE_DIR}/dev)

if (${HAWK_BUILD_TYPE} STREQUAL "opt") 
    set(HAWK_BUILD "NIST/Optimized_Implementation/avx2/hawk${HAWK_SEC_LEVEL}")
elseif (${HAWK_BUILD_TYPE} STREQUAL "ref")
    set(HAWK_BUILD "NIST/Reference_Implementation/hawk${HAWK_SEC_LEVEL}")
endif ()

set(HAWK_OBJECTS 
    ${HAWK}/${HAWK_BUILD}/hawk_kgen.o
    ${HAWK}/${HAWK_BUILD}/hawk_sign.o
    ${HAWK}/${HAWK_BUILD}/hawk_vrfy.o
    ${HAWK}/${HAWK_BUILD}/ng_fxp.o
    ${HAWK}/${HAWK_BUILD}/ng_hawk.o
    ${HAWK}/${HAWK_BUILD}/ng_mp31.o
    ${HAWK}/${HAWK_BUILD}/ng_ntru.o
    ${HAWK}/${HAWK_BUILD}/ng_poly.o
    ${HAWK}/${HAWK_BUILD}/ng_zint31.o
    ${HAWK}/${HAWK_BUILD}/sha3.o
    ${HAWK}/${HAWK_BUILD}/api.o
    ${HAWK}/${HAWK_BUILD}/rng.o
)

add_custom_target(hawk_make
    COMMAND make && cd ${HAWK_BUILD} && make
    WORKING_DIRECTORY ${HAWK}
    VERBATIM
)

add_library(hawk_wrapper hawk_wrapper.c)
add_dependencies(hawk_wrapper hawk_make)
target_link_libraries(hawk_wrapper PRIVATE ${HAWK_OBJECTS})

target_include_directories(hawk_wrapper PRIVATE 
    ${HAWK}/${HAWK_BUILD}
)
