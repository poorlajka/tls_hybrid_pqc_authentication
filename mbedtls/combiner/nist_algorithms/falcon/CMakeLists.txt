
if (${FALCON_BUILD_TYPE} STREQUAL "opt") 
    set(FALCON "${CMAKE_CURRENT_SOURCE_DIR}/falcon-round3/Optimized_Implementation/falcon${FALCON_SEC_LEVEL}/falcon${FALCON_SEC_LEVEL}avx2")
elseif (${FALCON_BUILD_TYPE} STREQUAL "ref")
    set(FALCON "${CMAKE_CURRENT_SOURCE_DIR}/falcon-round3/Reference_Implementation/falcon${FALCON_SEC_LEVEL}/falcon${FALCON_SEC_LEVEL}int")
endif ()

set(FALCON_BUILD ${FALCON}/build)
set(FALCON_OBJECTS 
    ${FALCON_BUILD}/codec.o
    ${FALCON_BUILD}/common.o
    ${FALCON_BUILD}/fft.o
    ${FALCON_BUILD}/fpr.o
    ${FALCON_BUILD}/keygen.o
    ${FALCON_BUILD}/nist.o
    ${FALCON_BUILD}/rng.o
    ${FALCON_BUILD}/shake.o
    ${FALCON_BUILD}/sign.o
    ${FALCON_BUILD}/vrfy.o
)

add_custom_target(falcon_make
    COMMAND make
    WORKING_DIRECTORY ${FALCON}
    VERBATIM
)

add_library(falcon_wrapper falcon_wrapper.c)
add_dependencies(falcon_wrapper falcon_make)
target_link_libraries(falcon_wrapper PRIVATE ${FALCON_OBJECTS})

target_include_directories(falcon_wrapper PRIVATE 
    ${FALCON}
)
