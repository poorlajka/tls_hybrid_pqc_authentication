set(MAYO "${CMAKE_CURRENT_SOURCE_DIR}/MAYO-C")

add_definitions(
    -DMAYO_BUILD_TYPE_${MAYO_BUILD_TYPE}
)

add_subdirectory(${MAYO})

add_library(
    mayo_wrapper 
    mayo_wrapper.c
)

# MAYO wrapper include headers
target_include_directories(mayo_wrapper PRIVATE
    ${MAYO}/include/mayo_${MAYO_SEC_LEVEL}
	${MAYO}/src
)

# MAYO wrapper link API
target_link_libraries(mayo_wrapper PRIVATE 
    mayo_${MAYO_SEC_LEVEL}_nistapi
)
