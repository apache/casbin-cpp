# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

cmake_minimum_required(VERSION 3.19)

set(CMAKE_WARN_DEPRECATED ON)
set(PY_CASBIN_VERSION 1.68.0)

if(APPLE AND NOT DEFINED CMAKE_OSX_DEPLOYMENT_TARGET)
    # The value of this variable should be set prior to the first project() command invocation
    # because it may influence configuration of the toolchain and flags.
    set(CMAKE_OSX_DEPLOYMENT_TARGET "10.13" CACHE STRING "Minimum OS X deployment version")
endif()

###############################################################################
# Project definition.

project(
    casbin
    VERSION 1.68.0
    DESCRIPTION "An authorization library that supports access control models like ACL, RBAC, ABAC in C/C++"
    HOMEPAGE_URL https://github.com/apache/casbin-cpp
    LANGUAGES CXX C
)

set(CMAKE_MODULE_PATH
    ${CMAKE_MODULE_PATH}
    ${PROJECT_SOURCE_DIR}/cmake/modules
)

# Some translation units exceed the default COFF section limit. This has to come
# after project(), which is what defines WIN32 and the compiler id.
if(MSVC)
    add_compile_options("/bigobj")
elseif(WIN32 AND CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    # MinGW spells the same thing differently, and rejects /bigobj outright.
    add_compile_options("-Wa,-mbig-obj")
endif()

###############################################################################
# Forbid in-source build.

if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
    message(FATAL_ERROR 
            "In-source build not allowed. Please make a new sub-directory and run CMake from there.")
endif()

###############################################################################
# Global CMake options.

option(CASBIN_BUILD_TEST "State whether to build test" ON)
option(CASBIN_BUILD_BENCHMARK "State whether to build benchmarks" ON)
option(INTENSIVE_BENCHMARK "State whether to build intensive benchmarks" OFF)
option(CASBIN_BUILD_PYTHON_BINDINGS "State whether to build python bindings" ON)
option(CASBIN_INSTALL "State whether to install casbin targets on the current system" ON)

# Intrinsic directory paths
set(CASBIN_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/casbin)
set(CASBIN_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(CASBIN_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)

# Do not output install messages.
if(NOT DEFINED CMAKE_INSTALL_MESSAGE)
    set(CMAKE_INSTALL_MESSAGE "LAZY")
endif()

# Change the path max size to avoid problem on Windows.
if(NOT DEFINED CMAKE_OBJECT_PATH_MAX)
    set(CMAKE_OBJECT_PATH_MAX 300)
endif()

# Setting to C++ standard to C++17
set(CMAKE_CXX_STANDARD 17)

# Standard bin/lib/include/share layout, needed by the install rules below and
# by the INSTALL_INTERFACE of the casbin target.
include(GNUInstallDirs)

###############################################################################
# Install external dependencies
# Some required targets may be created by third-party CMake configs, which 
# don't generally produce global targets. To guarantee all imported targets are 
# global, this module is included at the project root level.

include(FindExtPackages)

add_subdirectory(casbin)

if(CASBIN_BUILD_PYTHON_BINDINGS)
    add_subdirectory(pycasbin)
endif()

if(CASBIN_BUILD_TEST)
    enable_testing()
    add_subdirectory(tests)
endif()

##########################################
# "make format"
# "make check-format"
# Only support clang format for unix like operating system.

if(UNIX)
    # Expected directory structure.
    set(CASBIN_BUILD_SUPPORT_DIR "${CMAKE_SOURCE_DIR}/build_support")
    set(CASBIN_CLANG_SEARCH_PATH "/usr/local/bin" "/usr/bin" "/usr/local/opt/llvm/bin" "/usr/local/opt/llvm@8/bin"
            "/usr/local/Cellar/llvm/8.0.1/bin")

    # clang-format
    if (NOT DEFINED CLANG_FORMAT_BIN)
        # attempt to find the binary if user did not specify
        find_program(CLANG_FORMAT_BIN
                NAMES clang-format clang-format-8
                HINTS ${CASBIN_CLANG_SEARCH_PATH})
    endif()
    if ("${CLANG_FORMAT_BIN}" STREQUAL "CLANG_FORMAT_BIN-NOTFOUND")
        message(WARNING "Casbin couldn't find clang-format.")
    else()
        message(STATUS "Casbin found clang-format at ${CLANG_FORMAT_BIN}")
    endif()

    # clang-tidy
    if (NOT DEFINED CLANG_TIDY_BIN)
        # attempt to find the binary if user did not specify
        find_program(CLANG_TIDY_BIN
                NAMES clang-tidy clang-tidy-8
                HINTS ${CASBIN_CLANG_SEARCH_PATH})
    endif()
    if ("${CLANG_TIDY_BIN}" STREQUAL "CLANG_TIDY_BIN-NOTFOUND")
        message(WARNING "Casbin couldn't find clang-tidy.")
    else()
        # Output compile_commands.json
        set(CMAKE_EXPORT_COMPILE_COMMANDS 1)
        message(STATUS "Casbin found clang-tidy at ${CLANG_TIDY_BIN}")
    endif()

    string(CONCAT CASBIN_FORMAT_DIRS
            "${CASBIN_SOURCE_DIR},"
            "${CASBIN_INCLUDE_DIR},"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests,"
            )


    # runs clang format and updates files in place.
    add_custom_target(format ${CASBIN_BUILD_SUPPORT_DIR}/run_clang_format.py
            ${CLANG_FORMAT_BIN}
            ${CASBIN_BUILD_SUPPORT_DIR}/clang_format_exclusions.txt
            --source_dirs
            ${CASBIN_FORMAT_DIRS}
            --format_style
            "file"
            --fix
            --quiet
            )

    # runs clang format and exits with a non-zero exit code if any files need to be reformatted
    add_custom_target(check-format ${CASBIN_BUILD_SUPPORT_DIR}/run_clang_format.py
            ${CLANG_FORMAT_BIN}
            ${CASBIN_BUILD_SUPPORT_DIR}/clang_format_exclusions.txt
            --source_dirs
            ${CASBIN_FORMAT_DIRS}
            --format_style
            "file"
            --quiet
            )
endif()
##########################################
# Install casbin

if(CASBIN_INSTALL)
    message(CHECK_START "[casbin]: Configuring the casbin installation ...")

    include(CMakePackageConfigHelpers)

    set(CASBIN_INSTALL_CMAKEDIR "${CMAKE_INSTALL_LIBDIR}/cmake/casbin"
        CACHE STRING "Path to the installed casbin CMake package files")

    # Carry the exact source legal material into installed C++ packages.
    file(READ "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE" CASBIN_BINARY_LICENSE)
    string(FIND "${CASBIN_BINARY_LICENSE}" "setup.py contains build helper code" CASBIN_SOURCE_ONLY_LICENSE)
    if(CASBIN_SOURCE_ONLY_LICENSE GREATER -1)
        string(SUBSTRING "${CASBIN_BINARY_LICENSE}" 0 ${CASBIN_SOURCE_ONLY_LICENSE} CASBIN_BINARY_LICENSE)
    endif()
    file(READ "${CMAKE_CURRENT_SOURCE_DIR}/licenses/nlohmann-json-LICENSE.txt" CASBIN_JSON_LICENSE)
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/LICENSE-installed"
        "${CASBIN_BINARY_LICENSE}\nThe installed library includes code compiled from nlohmann/json (MIT):\n\n${CASBIN_JSON_LICENSE}")
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/LICENSE-installed"
        DESTINATION ${CMAKE_INSTALL_DATADIR}/casbin RENAME LICENSE)
    install(FILES NOTICE DISCLAIMER DESTINATION ${CMAKE_INSTALL_DATADIR}/casbin)

    # Installing headers
    install(
        DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/casbin
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    )

    # Installing the library itself. Without this the installed tree only ever
    # contained headers, so downstream projects had nothing to link against.
    install(
        TARGETS casbin
        EXPORT casbinTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )

    # Installing the CMake package files so that find_package(casbin) works
    # against the install prefix (and hence for package managers such as vcpkg)
    # instead of only against the CMake User Package Registry.
    install(
        EXPORT casbinTargets
        FILE casbinTargets.cmake
        NAMESPACE casbin::
        DESTINATION ${CASBIN_INSTALL_CMAKEDIR}
    )

    configure_package_config_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/cmake/casbinConfig.cmake.in
        ${CMAKE_CURRENT_BINARY_DIR}/casbinConfig.cmake
        INSTALL_DESTINATION ${CASBIN_INSTALL_CMAKEDIR}
    )

    write_basic_package_version_file(
        ${CMAKE_CURRENT_BINARY_DIR}/casbinConfigVersion.cmake
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY SameMajorVersion
    )

    install(
        FILES
            ${CMAKE_CURRENT_BINARY_DIR}/casbinConfig.cmake
            ${CMAKE_CURRENT_BINARY_DIR}/casbinConfigVersion.cmake
        DESTINATION ${CASBIN_INSTALL_CMAKEDIR}
    )

    # Also export the targets for the build tree, so that a project using
    # FetchContent/add_subdirectory can consume casbin:: without installing.
    export(
        EXPORT casbinTargets
        NAMESPACE casbin::
        FILE ${CMAKE_CURRENT_BINARY_DIR}/casbinTargets.cmake
    )

    message(CHECK_PASS " done")
    message(STATUS "[casbin]: Build the \"install\" target, then use find_package(casbin) and link against casbin::casbin")
endif()
