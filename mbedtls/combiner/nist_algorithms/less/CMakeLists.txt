set(LESS "LESS/Optimized_Implementation/avx2")
#set(LESS "LESS/Reference_Implementation")

set(SRC "${LESS}/lib")

set(SOURCES 
    ${SRC}/codes.c
    ${SRC}/fips202.c
    ${SRC}/keccakf1600.c
    ${SRC}/LESS.c
    ${SRC}/monomial.c
    ${SRC}/rng.c
    ${SRC}/seedtree.c
    ${SRC}/sign.c
    ${SRC}/utils.c
    ${SRC}/canonical.c
    ${SRC}/sort.c
    ${SRC}/transpose.c
    ${SRC}/KeccakP-1600-AVX2.s
    ${SRC}/transpose_avx2.c
)

add_library(
    less_lib STATIC 
    ${SOURCES}
)

target_compile_options(less_lib PRIVATE "-march=native")

add_library(
    less_wrapper
    less_wrapper.c
)

target_include_directories(less_lib PRIVATE
    ${LESS}/include
)

target_include_directories(less_wrapper PRIVATE
    ${LESS}/include
)

target_link_libraries(less_wrapper PRIVATE
    less_lib
)

