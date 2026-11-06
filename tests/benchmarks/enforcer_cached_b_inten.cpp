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

/* This is an intensive test file for benchmarking the performance of casbin::CachedEnforcer */

#include <benchmark/benchmark.h>
#include <casbin/casbin.h>

#include "config_path.h"

static void BenchmarkCachedRBACModelMedium(benchmark::State& state) {
    casbin::CachedEnforcer e(rbac_model_path, "", false);
    PoliciesValues p_policies(1000);
    // 1000 roles, 100 resources.
    for (int i = 0; i < 1000; ++i) p_policies[i] = {"group" + std::to_string(i), "data" + std::to_string(i / 10), "read"};

    e.AddPolicies(p_policies);

    // 10000 users.
    PoliciesValues g_policies(10000);
    for (int i = 0; i < 10000; ++i) g_policies[i] = {"user" + std::to_string(i), "group" + std::to_string(i / 10)};

    e.AddGroupingPolicies(g_policies);
    casbin::DataList params = {"user5001", "data150", "read"};
    for (auto _ : state) e.Enforce(params);
}

BENCHMARK(BenchmarkCachedRBACModelMedium);

static void BenchmarkCachedRBACModelLarge(benchmark::State& state) {
    casbin::CachedEnforcer e(rbac_model_path, "", false);

    // 10000 roles, 1000 resources.
    PoliciesValues p_policies(10000);
    for (int i = 0; i < 10000; ++i) p_policies[i] = {"group", std::to_string(i), "data", std::to_string(i / 10), "read"};
    e.AddPolicies(p_policies);

    // 100000 users.
    PoliciesValues g_policies(100000);
    for (int i = 0; i < 100000; ++i) {
        g_policies[i] = {"user" + std::to_string(i), "group", std::to_string(i / 10)};
    }
    e.AddGroupingPolicies(g_policies);
    casbin::DataList params = {"user50001", "data1500", "read"};
    for (auto _ : state) {
        e.Enforce(params);
    }
}

BENCHMARK(BenchmarkCachedRBACModelLarge);

static void BenchmarkCachedRBACModelMediumParallel(benchmark::State& state) {
    casbin::CachedEnforcer e(rbac_model_path, "", false);
    casbin::DataList params = {"user5001", "data150", "read"};
    if (state.thread_index == 0) {
        PoliciesValues p_policies(10000);
        for (int i = 0; i < 10000; ++i) p_policies[i] = {"group" + std::to_string(i), "data" + std::to_string(i / 10), "read"};
        e.AddPolicies(p_policies);

        PoliciesValues g_policies(100000);
        for (int i = 0; i < 100000; ++i) e.AddGroupingPolicy({"user" + std::to_string(i), "group" + std::to_string(i / 10)});
    }
    for (auto _ : state) {
        e.Enforce(params);
    }
}
// BENCHMARK(BenchmarkCachedRBACModelMediumParallel)->Threads(10);