
set(FAEST "${CMAKE_CURRENT_SOURCE_DIR}/faest-avx")
set(FAEST_SRC "${FAEST}/build_bench/submission/Additional_Implementations/avx2/faest_${FAEST_SEC_LEVEL}${FAEST_BALANCE}")

set(FAEST_LIB
    ${FAEST_SRC}/libfaest.a
    ${FAEST_SRC}/randomness_randombytes.o
)

add_custom_target(faest_make
    COMMAND meson setup build_bench --buildtype=release -Db_lto=true -Doptimization=3 && cd build_bench && meson compile prepare_nist && cd ${FAEST_SRC} && make 
    WORKING_DIRECTORY ${FAEST}
    VERBATIM
)

add_library(faest_wrapper faest_wrapper.c)

add_dependencies(faest_wrapper
    faest_make
)

target_include_directories(faest_wrapper PRIVATE
    ${FAEST_SRC}
)

target_link_libraries(faest_wrapper PRIVATE
    ${FAEST_LIB}
)





