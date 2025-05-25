set(SNOVA "${CMAKE_CURRENT_SOURCE_DIR}/SNOVA/src")

if(${SNOVA_SK_IS_SEED} EQUAL 1)
    set(
        SNOVA_SK_TYPE
        SSK
    )
else()
    set(
        SNOVA_SK_TYPE
        ESK
    )
endif()

if(${SNOVA_PK_EXPAND_SHAKE} EQUAL 1)
    set(
        SNOVA_PK_EXPAND
        _SHAKE
    )
else()
    set(
        SNOVA_PK_EXPAND
        ""
    )
endif()

set(
    SNOVA_CRYPTO_ALGNAME
    SNOVA_${SNOVA_V}_${SNOVA_O}_${SNOVA_L}${SNOVA_PK_EXPAND}
)

add_definitions(
    -Dv_SNOVA=${SNOVA_V}
    -Do_SNOVA=${SNOVA_O}
    -Dl_SNOVA=${SNOVA_L}
    -Dsk_is_seed=${SNOVA_SK_TYPE}
    -DCRYPTO_ALGNAME=${SNOVA_CRYPTO_ALGNAME} 
    -DPK_EXPAND_SHAKE=${SNOVA_PK_EXPAND} 
    -DOPTIMISATION=${SNOVA_OPTIMISATION} 
    -DFIXED_ABQ=2
)

set(SNOVA_LIB
    ${SNOVA}/build_libo/libsnovasym.a
)

set(SNOVA_OBJS
    ${SNOVA}/build/ct_functions.o
    ${SNOVA}/build/rng.o
    ${SNOVA}/build/sign.o
    ${SNOVA}/build/snova.o
)

# Turns out specifying sk is seed or pk expand to 0 when they are not used causes segfaults because god hates me so 
# I'm leaving it out here for now since I'm not planning to use it :) :)
add_custom_target(snova_make
    COMMAND make test_api SNOVA_V=${SNOVA_V} SNOVA_O=${SNOVA_O} SNOVA_L=${SNOVA_L} OPTIMISATION=${SNOVA_OPTIMISATION}
    WORKING_DIRECTORY ${SNOVA}
    VERBATIM
)

add_library(
    snova_wrapper STATIC
    snova_wrapper.c
)

target_compile_options(snova_wrapper PRIVATE
    -std=c11 -Wall -Wextra -Wpedantic -Werror -Wredundant-decls -Wshadow -Wvla -Wpointer-arith -ftree-vectorize -O3 -march=native -mtune=native
)

add_dependencies(snova_wrapper
    snova_make
)

target_link_libraries(snova_wrapper PRIVATE
    ${SNOVA_LIB}
    ${SNOVA_OBJS}
)

target_include_directories(snova_wrapper PRIVATE
    ${SNOVA}
)




