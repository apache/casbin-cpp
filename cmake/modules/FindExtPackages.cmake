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

###############################################################################
### Global package options ###

set(CMAKE_FIND_PACKAGE_NO_PACKAGE_REGISTRY ON CACHE BOOL
    "Disable CMake User Package Registry when finding packages")

set(CMAKE_FIND_PACKAGE_NO_SYSTEM_PACKAGE_REGISTRY ON CACHE BOOL
    "Disable CMake System Package Registry when finding packages")

###############################################################################
### Packages and versions ###

find_package(json 3.10.1 REQUIRED)

if(CASBIN_BUILD_TEST)
    # googletest
    # https://github.com/google/googletest
    find_package(googletest 1.11.0 REQUIRED)

    if(CASBIN_BUILD_BENCHMARK)
        # benchmark
        # https://github.com/google/benchmark
        find_package(benchmark 1.5.5 REQUIRED)
    endif()
endif()

if(CASBIN_BUILD_PYTHON_BINDINGS)
    # pybind11
    # https://github.com/pybind/pybind11
    find_package(pybind11 2.8.0 REQUIRED)
endif()
