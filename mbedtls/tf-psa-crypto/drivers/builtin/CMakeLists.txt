add_subdirectory(src)
#add_subdirectory("../../../combiner")
#\\wsl.localhost\Debian\home\viktor\tls-hybrid-authentication\mbedtls\tf-psa-crypto\drivers\builtin\CMakeLists.txt

file(GLOB src_builtin RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} src/*.c)

set(libs ${libs} combiner)

if(CMAKE_COMPILER_IS_GNUCC)
    set(LIBS_C_FLAGS -Wmissing-declarations -Wmissing-prototypes)
endif(CMAKE_COMPILER_IS_GNUCC)

if(CMAKE_COMPILER_IS_CLANG)
    set(LIBS_C_FLAGS -Wmissing-declarations -Wmissing-prototypes -Wdocumentation -Wno-documentation-deprecated-sync -Wunreachable-code)
endif(CMAKE_COMPILER_IS_CLANG)

if(CMAKE_COMPILER_IS_MSVC)
    option(MSVC_STATIC_RUNTIME "Build the libraries with /MT compiler flag" OFF)
    if(MSVC_STATIC_RUNTIME)
        foreach(flag_var
            CMAKE_C_FLAGS CMAKE_C_FLAGS_DEBUG CMAKE_C_FLAGS_RELEASE
            CMAKE_C_FLAGS_MINSIZEREL CMAKE_C_FLAGS_RELWITHDEBINFO
            CMAKE_C_FLAGS_CHECK)
            string(REGEX REPLACE "/MD" "/MT" ${flag_var} "${${flag_var}}")
        endforeach(flag_var)
    endif()
endif()

if(WIN32)
    set(libs ${libs} ws2_32 bcrypt)
endif(WIN32)

if(CMAKE_C_COMPILER_ID MATCHES "AppleClang")
    set(CMAKE_C_ARCHIVE_CREATE   "<CMAKE_AR> Scr <TARGET> <LINK_FLAGS> <OBJECTS>")
    set(CMAKE_C_ARCHIVE_FINISH   "<CMAKE_RANLIB> -no_warning_for_no_symbols -c <TARGET>")
endif()
if(CMAKE_CXX_COMPILER_ID MATCHES "AppleClang")
    set(CMAKE_CXX_ARCHIVE_CREATE "<CMAKE_AR> Scr <TARGET> <LINK_FLAGS> <OBJECTS>")
    set(CMAKE_CXX_ARCHIVE_FINISH "<CMAKE_RANLIB> -no_warning_for_no_symbols -c <TARGET>")
endif()

if(LINK_WITH_PTHREAD)
    set(libs ${libs} ${CMAKE_THREAD_LIBS_INIT})
endif()

set(builtin_target ${TF_PSA_CRYPTO_TARGET_PREFIX}builtin)
if (USE_STATIC_TF_PSA_CRYPTO_LIBRARY)
    set(builtin_static_target ${builtin_target})
endif()
set(target_libraries ${builtin_target})
if(USE_STATIC_TF_PSA_CRYPTO_LIBRARY AND USE_SHARED_TF_PSA_CRYPTO_LIBRARY)
    string(APPEND builtin_static_target "_static")
    list(APPEND target_libraries ${builtin_static_target})
endif()

set(p256m_target "${TF_PSA_CRYPTO_TARGET_PREFIX}p256m")
set(everest_target "${TF_PSA_CRYPTO_TARGET_PREFIX}everest")

if(USE_STATIC_TF_PSA_CRYPTO_LIBRARY)
    add_library(${builtin_static_target} STATIC ${src_builtin})
    set_base_compile_options(${builtin_static_target})
    target_compile_options(${builtin_static_target} PRIVATE ${LIBS_C_FLAGS})
    target_link_libraries(${builtin_static_target} PUBLIC ${libs} PRIVATE combiner)
    if(TARGET ${everest_target})
        target_link_libraries(${builtin_static_target} PUBLIC ${everest_target} PRIVATE combiner)
    endif()

    if(TARGET ${p256m_target})
        target_link_libraries(${builtin_static_target} PUBLIC ${p256m_target} PRIVATE combiner)
    endif()
endif(USE_STATIC_TF_PSA_CRYPTO_LIBRARY)

if(USE_SHARED_TF_PSA_CRYPTO_LIBRARY)
    add_library(${builtin_target} SHARED ${src_builtin})
    set_base_compile_options(${builtin_target})
    target_compile_options(${builtin_target} PRIVATE ${LIBS_C_FLAGS})
    target_link_libraries(${builtin_target} PUBLIC ${libs} PRIVATE combiner)
    if(TARGET ${everest_target})
        target_link_libraries(${builtin_target} PUBLIC ${everest_target} PRIVATE combiner)
    endif()

    if(TARGET ${p256m_target})
        target_link_libraries(${builtin_target} PUBLIC ${p256m_target} PRIVATE combiner)
    endif()
endif(USE_SHARED_TF_PSA_CRYPTO_LIBRARY)

install(TARGETS combiner
    EXPORT MbedTLSTargets
    DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

foreach (target IN LISTS target_libraries)
    target_include_directories(${target}
      PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
             $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
             $<BUILD_INTERFACE:${TF_PSA_CRYPTO_DIR}/include>
      PRIVATE ${TF_PSA_CRYPTO_DIR}/core)
    set_config_files_compile_definitions(${target})

    if(INSTALL_TF_PSA_CRYPTO_HEADERS)

      install(DIRECTORY include/mbedtls
        DESTINATION include
        FILE_PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
        DIRECTORY_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ
        GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
        FILES_MATCHING PATTERN "*.h")

    endif(INSTALL_TF_PSA_CRYPTO_HEADERS)

    install(TARGETS ${target}
      EXPORT MbedTLSTargets
      DESTINATION ${CMAKE_INSTALL_LIBDIR}
      PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

    install(TARGETS ${target}
      EXPORT TF-PSA-CryptoTargets
      DESTINATION ${CMAKE_INSTALL_LIBDIR}
      PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
endforeach(target)
