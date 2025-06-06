set(executables_mbedtls
    dh_client
    dh_server
)
add_dependencies(${programs_target} ${executables_mbedtls})

foreach(exe IN LISTS executables_mbedtls)
    add_executable(${exe} ${exe}.c $<TARGET_OBJECTS:mbedtls_test>)
    set_base_compile_options(${exe})
    target_link_libraries(${exe} ${mbedtls_target} ${CMAKE_THREAD_LIBS_INIT})
    target_include_directories(${exe} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../framework/tests/include)
endforeach()

set(executables_mbedcrypto
    dh_genprime
    ecdh_curve25519
    ecdsa
    gen_key
    key_app
    key_app_writer
    mpi_demo
    pk_encrypt
    pk_decrypt
    pk_sign
    pk_verify
    rsa_decrypt
    rsa_encrypt
    rsa_genkey
    rsa_sign
    rsa_sign_pss
    rsa_verify
    rsa_verify_pss
)
add_dependencies(${programs_target} ${executables_mbedcrypto})

foreach(exe IN LISTS executables_mbedcrypto)
    add_executable(${exe} ${exe}.c $<TARGET_OBJECTS:mbedtls_test>)
    set_base_compile_options(${exe})
    target_link_libraries(${exe} ${tfpsacrypto_target} ${CMAKE_THREAD_LIBS_INIT})
    target_include_directories(${exe} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../framework/tests/include)
endforeach()

install(TARGETS ${executables_mbedtls} ${executables_mbedcrypto}
        DESTINATION "bin"
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
