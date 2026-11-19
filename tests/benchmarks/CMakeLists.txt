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

add_definitions(-DCASBIN_PROJECT_DIR=${CMAKE_SOURCE_DIR})

set(CASBIN_BENCHMARK_SOURCE
    main.cpp
    model_b.cpp
    enforcer_cached_b.cpp
    management_api_b.cpp
    role_manager_b.cpp
)

set(CASBIN_INTENSIVE_BENCHMARK_SOURCE
    model_b_inten.cpp
    enforcer_cached_b_inten.cpp
    management_api_b_inten.cpp
    role_manager_b_inten.cpp
)

set(CASBIN_BENCHMARK_HEADER
    config_path.h
)

if(INTENSIVE_BENCHMARK STREQUAL ON)
    add_executable(casbin_benchmark ${CASBIN_BENCHMARK_SOURCE} ${CASBIN_INTENSIVE_BENCHMARK_SOURCE} ${CASBIN_BENCHMARK_HEADER})
else()
    add_executable(casbin_benchmark ${CASBIN_BENCHMARK_SOURCE} ${CASBIN_BENCHMARK_HEADER})
endif()

target_include_directories(casbin_benchmark PUBLIC ${CASBIN_INCLUDE_DIR})

if(UNIX)
    set_target_properties(casbin_benchmark PROPERTIES
      POSITION_INDEPENDENT_CODE ON
    )
endif()

target_link_libraries(
    casbin_benchmark
        PRIVATE
    benchmark
    casbin
    nlohmann_json::nlohmann_json
)
