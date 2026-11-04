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

if(CASBIN_BUILD_TEST)
  set(CMAKE_CXX_STANDARD 17)

  # set memcheck
  find_program( MEMORYCHECK_COMMAND valgrind )
  set( MEMORYCHECK_COMMAND_OPTIONS "--leak-check=full --error-exitcode=1" )
  include(CTest)

  add_definitions(-DCASBIN_PROJECT_DIR=${CMAKE_SOURCE_DIR})

  set(CASBIN_TEST_SOURCE
    built_in_functions_test.cpp
    matcher_release_test.cpp
    config_test.cpp
    enforcer_test.cpp
    enforcer_cached_test.cpp
    enforcer_synced_test.cpp
    management_api_test.cpp
    model_enforcer_test.cpp
    model_test.cpp
    rbac_api_with_domains_test.cpp
    rbac_api_test.cpp
    role_manager_test.cpp
    util_test.cpp
  )

  set(CASBIN_TEST_HEADER
    config_path.h
  )

  add_executable(casbintest ${CASBIN_TEST_SOURCE} ${CASBIN_TEST_HEADER})

  if(UNIX)
    set_target_properties(casbintest PROPERTIES
      POSITION_INDEPENDENT_CODE ON
    )
  endif()

  target_include_directories(casbintest PUBLIC ${CASBIN_INCLUDE_DIR})

  target_link_libraries(
    casbintest
    PRIVATE
    gtest_main
    casbin
    nlohmann_json::nlohmann_json
  )

  include(GoogleTest)
  gtest_discover_tests(casbintest PROPERTIES TIMEOUT 120)
endif()

if(CASBIN_BUILD_BENCHMARK)
  add_subdirectory(benchmarks)
endif()
