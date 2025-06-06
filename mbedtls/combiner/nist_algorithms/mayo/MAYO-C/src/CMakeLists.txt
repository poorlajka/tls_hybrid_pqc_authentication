# SPDX-License-Identifier: Apache-2.0

set(SOURCE_FILES_COMMON_SYS common/randombytes_system.c common/aes_c.c common/aes128ctr.c common/aes_neon.c common/fips202.c common/mem.c)

add_library(mayo_common_sys ${SOURCE_FILES_COMMON_SYS})
target_include_directories(mayo_common_sys PRIVATE common ../include)
target_compile_options(mayo_common_sys PUBLIC ${C_OPT_FLAGS})

set(SOURCE_FILES_COMMON_TEST common/randombytes_ctrdrbg.c common/aes_c.c common/aes128ctr.c common/aes_neon.c common/fips202.c common/mem.c)

add_library(mayo_common_test ${SOURCE_FILES_COMMON_TEST})
target_include_directories(mayo_common_test PRIVATE common ../include)
target_compile_options(mayo_common_test PUBLIC ${C_OPT_FLAGS})

if (ENABLE_CT_TESTING)
    target_compile_definitions(mayo_common_sys PUBLIC ENABLE_CT_TESTING)
    target_compile_definitions(mayo_common_test PUBLIC ENABLE_CT_TESTING)
endif()

if (ENABLE_AESNI)
    message("AES-NI enabled")
    target_compile_definitions(mayo_common_sys PUBLIC ENABLE_AESNI)
    target_compile_definitions(mayo_common_test PUBLIC ENABLE_AESNI)
endif()

if (ENABLE_AESNEON)
    message("AES-NEON enabled")
    target_compile_definitions(mayo_common_sys PUBLIC ENABLE_AESNEON)
    target_compile_definitions(mayo_common_test PUBLIC ENABLE_AESNEON)
endif()

set(SOURCE_FILES_MAYO mayo.c params.c arithmetic.c)

if (${MAYO_BUILD_TYPE} MATCHES "avx2")
    message("Building for avx2")
    set(INC_PLATFORM ${PROJECT_SOURCE_DIR}/src/AVX2 ${PROJECT_SOURCE_DIR}/src/generic)
    add_definitions(-DMAYO_AVX)
elseif (${MAYO_BUILD_TYPE} MATCHES "neon")
    message("Building for neon")
    set(INC_PLATFORM ${PROJECT_SOURCE_DIR}/src/neon ${PROJECT_SOURCE_DIR}/src/generic)
    add_definitions(-DMAYO_NEON)
else()
    set(INC_PLATFORM ${PROJECT_SOURCE_DIR}/src/generic)
endif()

if (ENABLE_PARAMS_DYNAMIC)
    # mayo and mayo_test libraries
    add_library(mayo ${SOURCE_FILES_MAYO})
    target_link_libraries(mayo PUBLIC mayo_common_sys)
    target_include_directories(mayo PUBLIC ../include . PRIVATE common ${INC_PLATFORM})
    add_library(mayo_test ${SOURCE_FILES_MAYO})
    target_link_libraries(mayo_test PUBLIC mayo_common_test)
    target_include_directories(mayo_test PUBLIC ../include . PRIVATE common ${INC_PLATFORM})

    target_compile_definitions(mayo PUBLIC ENABLE_PARAMS_DYNAMIC)
    target_compile_definitions(mayo_test PUBLIC ENABLE_PARAMS_DYNAMIC)

    # mayo_<x>_nistapi libraries
    foreach(MVARIANT ${MVARIANT_S})
        string(TOLOWER ${MVARIANT} MVARIANT_LOWER)
        set(SOURCE_FILES_VARIANT ${MVARIANT_LOWER}/api.c)
        add_library(${MVARIANT_LOWER}_nistapi ${SOURCE_FILES_VARIANT})
        target_link_libraries(${MVARIANT_LOWER}_nistapi PRIVATE mayo)
        target_compile_definitions(${MVARIANT_LOWER}_nistapi PUBLIC ENABLE_PARAMS_DYNAMIC)
        target_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/${MVARIANT_LOWER}_nistapi PUBLIC ${MVARIANT_LOWER} ${INC_PLATFORM})
        add_library(${MVARIANT_LOWER}_test_nistapi ${SOURCE_FILES_VARIANT})
        target_link_libraries(${MVARIANT_LOWER}_test_nistapi PRIVATE mayo_test)
        target_compile_definitions(${MVARIANT_LOWER}_test_nistapi PUBLIC ENABLE_PARAMS_DYNAMIC)
        target_include_directories(${MVARIANT_LOWER}_test_nistapi PUBLIC ${MVARIANT_LOWER} ${INC_PLATFORM})
    endforeach()

else()
    FOREACH(MVARIANT ${MVARIANT_S})
        string(TOLOWER ${MVARIANT} MVARIANT_LOWER)
        add_library(${MVARIANT_LOWER} ${SOURCE_FILES_MAYO})
        target_link_libraries(${MVARIANT_LOWER} PUBLIC mayo_common_sys)
        target_include_directories(${MVARIANT_LOWER} PUBLIC ../include . PRIVATE common ${INC_PLATFORM})
        add_library(${MVARIANT_LOWER}_test ${SOURCE_FILES_MAYO})
        target_link_libraries(${MVARIANT_LOWER}_test PUBLIC mayo_common_test)
        target_include_directories(${MVARIANT_LOWER}_test PUBLIC ../include . PRIVATE common ${INC_PLATFORM})
        target_compile_definitions(${MVARIANT_LOWER} PUBLIC MAYO_VARIANT=${MVARIANT})
        target_compile_definitions(${MVARIANT_LOWER}_test PUBLIC MAYO_VARIANT=${MVARIANT})
    ENDFOREACH()

    foreach(MVARIANT ${MVARIANT_S})
        string(TOLOWER ${MVARIANT} MVARIANT_LOWER)
        set(SOURCE_FILES_VARIANT ${MVARIANT_LOWER}/api.c)
        add_library(${MVARIANT_LOWER}_nistapi ${SOURCE_FILES_VARIANT})
        target_link_libraries(${MVARIANT_LOWER}_nistapi PRIVATE ${MVARIANT_LOWER})
        target_include_directories(${MVARIANT_LOWER}_nistapi PUBLIC ${MVARIANT_LOWER} PUBLIC ../include ${INC_PLATFORM})
        add_library(${MVARIANT_LOWER}_test_nistapi ${SOURCE_FILES_VARIANT})
        target_link_libraries(${MVARIANT_LOWER}_test_nistapi PRIVATE ${MVARIANT_LOWER}_test)
        target_include_directories(${MVARIANT_LOWER}_test_nistapi PUBLIC ${MVARIANT_LOWER} ${INC_PLATFORM})
        target_compile_definitions(${MVARIANT_LOWER}_nistapi PUBLIC MAYO_VARIANT=${MVARIANT})
        target_compile_definitions(${MVARIANT_LOWER}_test_nistapi PUBLIC MAYO_VARIANT=${MVARIANT})
    endforeach()
endif()

