cmake_minimum_required(VERSION 3.15)

project(
    "net"
    VERSION 0.1.0
    LANGUAGES CXX
)

if(PROJECT_SOURCE_DIR STREQUAL PROJECT_BINARY_DIR)
    message(
        FATAL_ERROR
            "In-source builds not allowed. Please make a new directory (called a build directory) and run CMake from there."
    )
endif()

if(NOT DEFINED ${PROJECT_NAME}_MASTER_PROJECT)
    set(${PROJECT_NAME}_MASTER_PROJECT OFF)

    if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
        set(${PROJECT_NAME}_MASTER_PROJECT ON)
        message(STATUS "CMake version: ${CMAKE_VERSION}")
    endif()
endif()

if(UNIX)
    add_compile_options("$<$<CONFIG:DEBUG>:-D_DEBUG>")
endif()

string(TOLOWER ${PROJECT_NAME} PROJECT_NAME_LOWERCASE)
string(TOUPPER ${PROJECT_NAME} PROJECT_NAME_UPPERCASE)

option(BUILD_SHARED_LIBS "Build shared libraries" ON)
option(${PROJECT_NAME}_BUILD_EXAMPLES "Build the examples" OFF)
option(${PROJECT_NAME}_INSTALL "Generate the install target" ON)

if(BUILD_SHARED_LIBS)
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS OFF)
    set(CMAKE_CXX_VISIBILITY_PRESET hidden)
    set(CMAKE_VISIBILITY_INLINES_HIDDEN 1)
endif()

find_package(Threads REQUIRED)

function(download_and_include file_name url)
    if(NOT EXISTS "${CMAKE_BINARY_DIR}/${file_name}")
        file(DOWNLOAD "${url}" "${CMAKE_BINARY_DIR}/${file_name}" TLS_VERIFY ON)
    endif()

    include(${CMAKE_BINARY_DIR}/${file_name})
endfunction()

download_and_include(
    "CPM.cmake"
    "https://github.com/cpm-cmake/CPM.cmake/releases/latest/download/get_cpm.cmake"
)

cpmfindpackage(
    NAME
    "OpenSSL"
    GITHUB_REPOSITORY
    "Xminent/openssl-cmake"
    GIT_TAG
    "master"
    OPTIONS
    "BUILD_SHARED_LIBS ON"
    "WITH_APPS OFF"
)
if(NOT EXISTS "${CMAKE_BINARY_DIR}/_deps/span-src/tcb/span.hpp")
    file(
        DOWNLOAD
        "https://raw.githubusercontent.com/tcbrindle/span/master/include/tcb/span.hpp"
        "${CMAKE_BINARY_DIR}/_deps/span-src/tcb/span.hpp"
        TLS_VERIFY ON
    )
endif()

add_library(span INTERFACE)
target_sources(
    span
    INTERFACE $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/_deps/span-src/tcb/span.hpp>
)
target_include_directories(
    span INTERFACE $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/_deps/span-src>
                   $<INSTALL_INTERFACE:include>
)

if(NOT EXISTS "${CMAKE_BINARY_DIR}/_deps/tl-expected-src/tl/expected.hpp")
    file(
        DOWNLOAD
        "https://raw.githubusercontent.com/TartanLlama/expected/master/include/tl/expected.hpp"
        "${CMAKE_BINARY_DIR}/_deps/tl-expected-src/tl/expected.hpp"
        TLS_VERIFY ON
    )
endif()

add_library(tl-expected INTERFACE)
target_sources(
    tl-expected
    INTERFACE
        $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/_deps/tl-expected-src/tl/expected.hpp>
)
target_include_directories(
    tl-expected
    INTERFACE $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/_deps/tl-expected-src>
              $<INSTALL_INTERFACE:include>
)

file(GLOB_RECURSE sources CONFIGURE_DEPENDS "include/*.hpp" "src/*.cpp")

add_library(${PROJECT_NAME} ${sources})

include(GenerateExportHeader)

generate_export_header(
    ${PROJECT_NAME} EXPORT_FILE_NAME export/${PROJECT_NAME_LOWERCASE}/export.h
)

target_compile_definitions(
    ${PROJECT_NAME}
    PUBLIC
        $<$<NOT:$<BOOL:${BUILD_SHARED_LIBS}>>:${PROJECT_NAME_UPPERCASE}_STATIC_DEFINE>
)

target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_17)
target_include_directories(
    ${PROJECT_NAME}
    PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
           $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/export>
           $<INSTALL_INTERFACE:include>
)

set(${PROJECT_NAME}_TARGETS ${PROJECT_NAME} span tl-expected)
set(SEPARATE_DEPENDENCIES "")

if(OpenSSL_ADDED)
    target_link_libraries(${PROJECT_NAME} PRIVATE ssl crypto)
    list(APPEND ${PROJECT_NAME}_TARGETS ssl crypto)
else()
    target_link_libraries(${PROJECT_NAME} PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    list(APPEND SEPARATE_DEPENDENCIES "OpenSSL")
endif()

target_link_libraries(
    ${PROJECT_NAME}
    PRIVATE Threads::Threads
    PUBLIC span tl-expected
)

if(WIN32)
    target_link_libraries(${PROJECT_NAME} PRIVATE wsock32 ws2_32)
endif()

add_library(${PROJECT_NAME}::${PROJECT_NAME} ALIAS ${PROJECT_NAME})

set(${PROJECT_NAME}_WARNINGS_AS_ERRORS ON)

download_and_include(
    "CompilerWarnings.cmake"
    "https://raw.githubusercontent.com/filipdutescu/modern-cpp-template/master/cmake/CompilerWarnings.cmake"
)

set_project_warnings(${PROJECT_NAME})

if(${PROJECT_NAME}_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

if(${PROJECT_NAME}_INSTALL)
    include(GNUInstallDirs)

    install(
        TARGETS ${${PROJECT_NAME}_TARGETS}
        EXPORT ${PROJECT_NAME}Targets
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        INCLUDES
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    )

    install(
        EXPORT ${PROJECT_NAME}Targets
        FILE ${PROJECT_NAME}Targets.cmake
        NAMESPACE ${PROJECT_NAME}::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
    )

    install(DIRECTORY ${CMAKE_BINARY_DIR}/_deps/span-src/tcb
            DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    )

    install(DIRECTORY ${CMAKE_BINARY_DIR}/_deps/tl-expected-src/tl
            DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    )

    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/cmake/version.h.in
        include/${PROJECT_NAME_LOWERCASE}/version.h @ONLY
    )

    install(
        FILES
            ${CMAKE_CURRENT_BINARY_DIR}/export/${PROJECT_NAME_LOWERCASE}/export.h
            ${CMAKE_CURRENT_BINARY_DIR}/include/${PROJECT_NAME_LOWERCASE}/version.h
        DESTINATION include/${PROJECT_NAME_LOWERCASE}
    )

    install(
        DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/${PROJECT_NAME_LOWERCASE}
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    )

    include(CMakePackageConfigHelpers)

    write_basic_package_version_file(
        ${PROJECT_NAME}ConfigVersion.cmake
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY SameMajorVersion
    )

    configure_package_config_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/cmake/Config.cmake.in
        ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake
        INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
    )

    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake
                  ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
    )

    set(CPACK_PACKAGE_VENDOR Xminent)
    set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "A networking library for C++")
    set(CPACK_PACKAGE_DESCRIPTION "A networking library for C++")
    set(CPACK_PACKAGE_CONTACT "mail@xminent.com")
    set(CPACK_DEBIAN_PACKAGE_DESCRIPTION "A networking library for C++")

    if(WIN32)
        set(CPACK_GENERATOR ZIP)
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        set(CPACK_GENERATOR "DEB;RPM")
    else()
        set(CPACK_GENERATOR "TBZ2")
    endif()

    include(CPack)
endif()
