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

set(CASBIN_SOURCE_FILES
    enforcer.cpp
    enforcer_cached.cpp
    enforcer_synced.cpp
    selected_policies.cpp
    internal_api.cpp
    logger.cpp
    management_api.cpp
    pch.cpp
    rbac_api.cpp
    rbac_api_with_domains.cpp
    config/config.cpp
    effect/default_effector.cpp
    ip_parser/exception/parser_exception.cpp
    ip_parser/parser/allFF.cpp
    ip_parser/parser/CIDRMask.cpp
    ip_parser/parser/dtoi.cpp
    ip_parser/parser/equal.cpp
    ip_parser/parser/IP.cpp
    ip_parser/parser/IPNet.cpp
    ip_parser/parser/IPv4.cpp
    ip_parser/parser/parseCIDR.cpp
    ip_parser/parser/parseIP.cpp
    ip_parser/parser/parseIPv4.cpp
    ip_parser/parser/parseIPv6.cpp
    ip_parser/parser/Print.cpp
    ip_parser/parser/xtoi.cpp
    model/assertion.cpp
    model/function.cpp
    model/model.cpp
    model/evaluator.cpp
    model/policy_collection.cpp
    persist/file_adapter/batch_file_adapter.cpp
    persist/file_adapter/file_adapter.cpp
    persist/file_adapter/filtered_file_adapter.cpp
    persist/adapter.cpp
    persist/default_watcher.cpp
    persist/default_watcher_ex.cpp
    persist/string_adapter.cpp
    rbac/default_role_manager.cpp
    util/array_equals.cpp
    util/array_remove_duplicates.cpp
    util/array_to_string.cpp
    util/built_in_functions.cpp
    util/ends_with.cpp
    util/escape_assertion.cpp
    util/find_all_occurences.cpp
    util/is_instance_of.cpp
    util/join.cpp
    util/join_slice.cpp
    util/remove_comments.cpp
    util/set_subtract.cpp
    util/split.cpp
    util/ticker.cpp
    util/trim.cpp
    util/eval.cpp
)

# Setting to C++ standard to C++17
set(CMAKE_CXX_STANDARD 17)

add_library(casbin STATIC ${CASBIN_SOURCE_FILES})
# So that add_subdirectory()/FetchContent consumers can use the same name as
# find_package() consumers.
add_library(casbin::casbin ALIAS casbin)

target_precompile_headers(casbin PRIVATE ${CASBIN_INCLUDE_DIR}/casbin/pch.h)

# Consumers must see the headers too, both from the build tree and from an
# installed prefix, otherwise find_package(casbin) hands out a target that
# cannot be compiled against.
target_include_directories(casbin
    PUBLIC
        $<BUILD_INTERFACE:${CASBIN_INCLUDE_DIR}>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
find_package(Threads REQUIRED)
target_compile_features(casbin PUBLIC cxx_std_17)
target_link_libraries(casbin PUBLIC nlohmann_json::nlohmann_json Threads::Threads)

# Keep the platform default naming (libcasbin.a / casbin.lib) so that the
# installed library looks like every other system library and can be picked up
# with a plain -lcasbin.
set_target_properties(casbin PROPERTIES
    VERSION ${PROJECT_VERSION}
)

if(UNIX)
    set_target_properties(casbin PROPERTIES POSITION_INDEPENDENT_CODE ON)
endif()
