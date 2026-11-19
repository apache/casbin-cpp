/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

/* This is an intensive test file for benchmarking the performance of casbin::RoleManager */

#include <benchmark/benchmark.h>
#include <casbin/casbin.h>

#include "config_path.h"

static std::vector<std::string> params(3);
static std::vector<std::string> g_params(2);

static void BenchmarkRoleManagerMedium(benchmark::State& state) {
    casbin::Enforcer e(rbac_model_path);
    // Do not rebuild the role inheritance relations for every AddGroupingPolicy() call.
    e.EnableAutoBuildRoleLinks(false);

    // 1000 roles, 100 resources.

    for (int i = 0; i < 1000; ++i) params = {"group" + std::to_string(i), "data" + std::to_string(i / 10), "read"}, e.AddPolicy(params);

    // 10000 users.

    for (int i = 0; i < 10000; ++i) g_params = {"user" + std::to_string(i), "group" + std::to_string(i / 10)}, e.AddGroupingPolicy(g_params);

    e.BuildRoleLinks();

    auto rm = e.GetRoleManager();

    for (auto _ : state) {
        for (int j = 0; j < 1000; ++j) rm->HasLink("user501", "group" + std::to_string(j));
    }
}

BENCHMARK(BenchmarkRoleManagerMedium);

static void BenchmarkRoleManagerLarge(benchmark::State& state) {
    casbin::Enforcer e(rbac_model_path);

    // 10000 roles, 1000 resources.

    for (int i = 0; i < 10000; ++i) params = {"group" + std::to_string(i), "data" + std::to_string(i / 10), "read"}, e.AddPolicy(params);

    // 100000 users.

    for (int i = 0; i < 100000; ++i) g_params = {"user" + std::to_string(i), "group" + std::to_string(i / 10)}, e.AddGroupingPolicy(g_params);

    auto rm = e.GetRoleManager();

    for (auto _ : state) {
        for (int j = 0; j < 10000; ++j) rm->HasLink("user501", "group" + std::to_string(j));
    }
}

BENCHMARK(BenchmarkRoleManagerLarge);