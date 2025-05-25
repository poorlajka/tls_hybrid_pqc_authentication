
set(SQISIGN_SEC_LEVELS "lvl1" "lvl3" "lvl5")
if(NOT SQISIGN_SEC_LEVEL IN_LIST SQISIGN_SEC_LEVELS)
    message(FATAL_ERROR "SQISIGN_SEC_LEVEL is not correctly defined! Should be one of ${SQISIGN_SEC_LEVELS}")
endif()

set(SQISIGN_BUILD_TYPES "ref" "opt" "broadwell" "arm64crypto")
if(NOT SQISIGN_BUILD_TYPE IN_LIST SQISIGN_BUILD_TYPES)
    message(FATAL_ERROR "SQISIGN_BUILD_TYPE is not correctly defined! Should be one of ${SQISIGN_BUILD_TYPES}")
endif()

if (${SQISIGN_BUILD_TYPE} MATCHES "ref")
  add_compile_definitions(SQISIGN_BUILD_TYPE_REF SQISIGN_GF_IMPL_REF)
elseif (${SQISIGN_BUILD_TYPE} MATCHES "opt")
  add_compile_definitions(SQISIGN_BUILD_TYPE_OPT SQISIGN_GF_IMPL_REF)
elseif (${SQISIGN_BUILD_TYPE} MATCHES "broadwell")
  add_compile_definitions(SQISIGN_BUILD_TYPE_BROADWELL SQISIGN_GF_IMPL_BROADWELL)
elseif (${SQISIGN_BUILD_TYPE} MATCHES "arm64crypto")
  add_compile_definitions(SQISIGN_BUILD_TYPE_ARM64CRYPTO SQISIGN_GF_IMPL_REF)
endif()

set(SQISIGN "the-sqisign")
set(SQISIGN_SRC "${SQISIGN}/src")
set(SQISIGN_INCLUDE "${SQISIGN}/include")
set(GF_RADIX 64)

add_compile_definitions(ENABLE_SIGN)

include(${SQISIGN}/.cmake/flags.cmake)
include(${SQISIGN}/.cmake/sanitizers.cmake)
include(${SQISIGN}/.cmake/target.cmake)

add_subdirectory(${SQISIGN})

add_library(sqisign_wrapper sqisign_wrapper.c)
target_link_libraries(sqisign_wrapper PRIVATE sqisign_${SQISIGN_SEC_LEVEL}_nistapi)
target_include_directories(sqisign_wrapper PRIVATE ${SQISIGN_INCLUDE} ${SQISIGN_SRC}/${SQISIGN_SEC_LEVEL})
target_compile_definitions(sqisign_wrapper PUBLIC SQISIGN_VARIANT=${SQISIGN_SEC_LEVEL})
