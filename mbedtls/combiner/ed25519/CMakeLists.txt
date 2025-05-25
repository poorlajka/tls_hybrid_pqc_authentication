cmake_minimum_required(VERSION 3.15...3.31)

project(
	edd25519
	VERSION 1.0
	LANGUAGES C CXX ASM
)
set(SRC "${CMAKE_CURRENT_SOURCE_DIR}/src")

add_library(ed25519 STATIC
    "${SRC}/ed25519_wrapper.c"
    "${SRC}/add_scalar.c"
    "${SRC}/fe.c"
    "${SRC}/ge.c"
    "${SRC}/key_exchange.c"
    "${SRC}/keypair.c"
    "${SRC}/sc.c"
    "${SRC}/seed.c"
    "${SRC}/sha512.c"
    "${SRC}/sign.c"
    "${SRC}/verify.c"
)

target_include_directories(ed25519 PRIVATE 
    "${SRC}"
)

add_executable(
    ed25519_test 
    "${SRC}/ed25519_test.c"
)

target_link_libraries(ed25519_test PRIVATE 
    ed25519
)

