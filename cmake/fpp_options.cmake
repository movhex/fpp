option(OPTION_BUILD_CLI "Build program with CLI" ON)
# 
# TODO: add CMAKE_DEPENDENT_OPTION
# 

if (OPTION_BUILD_CLI)
    target_compile_definitions(${PROJECT_NAME} PRIVATE FPP_BUILD_CLI)
else()
    target_compile_definitions(${PROJECT_NAME} PRIVATE FPP_BUILD_GUI)
endif()
