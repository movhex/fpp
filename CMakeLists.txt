cmake_minimum_required(VERSION 3.10.0)

project(fpp
    VERSION 0.1.1
    LANGUAGES C CXX
    DESCRIPTION "Files Protection Program"
    HOMEPAGE_URL "https://github.com/movhex/fpp"
)

add_executable(${PROJECT_NAME})

include(cmake/fpp_options.cmake)

target_include_directories(${PROJECT_NAME} PRIVATE include)

target_sources(${PROJECT_NAME}
PRIVATE
    src/core/encrypt_file.c
    src/core/aes128.c
    src/core/aes256.c
    src/core/blowfish.c
    src/core/cast5.c
    src/core/camellia128.c
    src/core/camellia256.c
    src/core/pbkdf2.c
    src/core/getpass.c
    src/core/random.c
    src/core/memory.c
    src/core/errcodes.c
    src/core/log.c
)

if (OPTION_BUILD_CLI)
    target_sources(${PROJECT_NAME} PRIVATE src/cli/main.c)
else()
    target_sources(${PROJECT_NAME} PRIVATE src/gui/main.cpp)
endif()

target_compile_options(${PROJECT_NAME}
PRIVATE
    -Wall
    -Wextra
    -Wno-uninitialized # -Wuninitialized
)

target_compile_features(${PROJECT_NAME} PRIVATE c_std_99)
target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_14)

if (NOT CMAKE_BUILD_TYPE)
    set (build_type release)
else()
    string(TOLOWER ${CMAKE_BUILD_TYPE} build_type)
endif()

if (build_type STREQUAL debug)
    target_compile_options(${PROJECT_NAME} PRIVATE -g3 -O0)
    target_compile_definitions(${PROJECT_NAME} PRIVATE
        FPP_DEBUG
        FPP_HAVE_VALGRIND
    )
elseif (build_type STREQUAL release)
    target_compile_options(${PROJECT_NAME} PRIVATE -g0 -O3)
endif()

target_link_libraries(${PROJECT_NAME}
    ${CMAKE_REQUIRED_LIBRARIES}
    ${ALL_LIBRARIES}
)

target_link_libraries(${PROJECT_NAME} ssl crypto)

string(TOLOWER ${CMAKE_SYSTEM_NAME} system_name)
if (system_name STREQUAL windows)
    target_link_libraries(${PROJECT_NAME} ws2_32)
else()
    target_link_libraries(${PROJECT_NAME} pthread)
    target_link_libraries(${PROJECT_NAME} ${CMAKE_DL_LIBS})
endif()
