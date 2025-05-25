
set(CROSS "CROSS-implementation/Optimized_Implementation")

set(CROSS_REF "CROSS-implementation/Reference_Implementation")

set(SRC "${CROSS}/lib")

set(SOURCES 
    ${SRC}/CROSS.c 
    ${SRC}/fips202x4.c
    ${SRC}/KeccakP-1600-times4-SIMD256.c
    ${SRC}/merkle.c 
    ${SRC}/seedtree.c 

    ${CROSS_REF}/lib/csprng_hash.c
    ${CROSS_REF}/lib/keccakf1600.c
    ${CROSS_REF}/lib/fips202.c
    ${CROSS_REF}/lib/sign.c
    ${CROSS_REF}/lib/pack_unpack.c
)


add_library(
    cross_wrapper
    cross_wrapper.c
    ${SOURCES}
)

target_include_directories(cross_wrapper PRIVATE
    ${CROSS}/include
    ${CROSS_REF}/include
)

