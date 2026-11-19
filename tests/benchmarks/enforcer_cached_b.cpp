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

/* This is a test file for benchmarking the performance of casbin::CachedEnforcer */

#include <benchmark/benchmark.h>
#include <casbin/casbin.h>

#include "config_path.h"

static const PoliciesValues s_policy({{"alice", "data1", "read"}, {"bob", "data2", "write"}});

static bool rawEnforce(const std::string& sub, const std::string& obj, const std::string& act) {
    for (const auto& rule : s_policy) {
        if (rule[0] == sub && rule[1] == obj && rule[2] == act)
            return true;
    }
    return false;
}

static void BenchmarkCachedRaw(benchmark::State& state) {
    for (auto _ : state) rawEnforce("alice", "data1", "read");
}

BENCHMARK(BenchmarkCachedRaw);

static void BenchmarkCachedBasicModel(benchmark::State& state) {
    casbin::CachedEnforcer e(basic_model_path, basic_policy_path, false);
    casbin::DataList request = {"alice", "data1", "read"};
    for (auto _ : state) e.Enforce(request);
}

BENCHMARK(BenchmarkCachedBasicModel);

static void BenchmarkCachedRBACModel(benchmark::State& state) {
    casbin::CachedEnforcer e(rbac_model_path, rbac_policy_path, false);
    casbin::DataList request = {"alice", "data2", "read"};
    for (auto _ : state) e.Enforce(request);
}

BENCHMARK(BenchmarkCachedRBACModel);

static void BenchmarkCachedRBACModelSmall(benchmark::State& state) {
    casbin::CachedEnforcer e(rbac_model_path, "", false);
    // 100 roles, 10 resources.
    for (int i = 0; i < 100; ++i) e.AddPolicy({"group" + std::to_string(i), "data" + std::to_string(i / 10), "read"});
    // 1000 users.
    for (int i = 0; i < 1000; ++i) e.AddGroupingPolicy({"user" + std::to_string(i), "group", std::to_string(i / 10)});
    casbin::DataList params = {"user501", "data9", "read"};
    for (auto _ : state) e.Enforce(params);
}

BENCHMARK(BenchmarkCachedRBACModelSmall);

static void BenchmarkCachedRBACModelWithResourceRoles(benchmark::State& state) {
    casbin::CachedEnforcer e(rbac_with_resource_roles_model_path, rbac_with_resource_roles_policy_path, false);

    casbin::DataList params = {"alice", "data1", "read"};
    for (auto _ : state) {
        e.Enforce(params);
    }
}

BENCHMARK(BenchmarkCachedRBACModelWithResourceRoles);

static void BenchmarkCachedRBACModelWithDomains(benchmark::State& state) {
    casbin::CachedEnforcer e(rbac_with_domains_model_path, rbac_with_domains_policy_path, false);

    casbin::DataList params = {"alice", "domain1", "data1", "read"};

    for (auto _ : state) {
        e.Enforce(params);
    }
}

BENCHMARK(BenchmarkCachedRBACModelWithDomains);

// ---- TODO ----
// static void BenchmarkCachedABACModel(benchmark::State& state) {
//     casbin::CachedEnforcer e(abac_model_path, false);
//     auto data1 = casbin::GetData({
//         {"Name", "data1"},
//         {"Owner", "alice"}
//     });

//     casbin::DataList params = {"alice", data1, "read"};
//     for (auto _ : state)
//     {
//         e.Enforce(params);
//     }
// }

static void BenchmarkCachedKeyMatchModel(benchmark::State& state) {
    casbin::CachedEnforcer e(keymatch_model_path, keymatch_policy_path, false);
    casbin::DataList params = {"alice", "/alice_data/resource1", "GET"};
    for (auto _ : state) {
        e.Enforce(params);
    }
}

BENCHMARK(BenchmarkCachedKeyMatchModel);

static void BenchmarkCachedRBACModelWithDeny(benchmark::State& state) {
    casbin::CachedEnforcer e(rbac_with_deny_model_path, rbac_with_deny_policy_path, false);

    casbin::DataList params = {"alice", "data1", "read"};
    for (auto _ : state) {
        e.Enforce(params);
    }
}

BENCHMARK(BenchmarkCachedRBACModelWithDeny);

static void BenchmarkCachedPriorityModel(benchmark::State& state) {
    casbin::CachedEnforcer e(priority_model_path, priority_policy_path, false);

    casbin::DataList params = {"alice", "data1", "read"};

    for (auto _ : state) e.Enforce(params);
}

BENCHMARK(BenchmarkCachedPriorityModel);
