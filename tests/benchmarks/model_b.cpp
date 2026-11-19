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

/* This is a test file for benchmarking the performance of casbin::Model */

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

static void BenchmarkRaw(benchmark::State& state) {
    for (auto _ : state) rawEnforce("alice", "data1", "read");
}

BENCHMARK(BenchmarkRaw);

static void BenchmarkBasicModel(benchmark::State& state) {
    casbin::Enforcer e(basic_model_path, basic_policy_path, false);

    casbin::DataList params = {"alice", "data1", "read"};

    for (auto _ : state) e.Enforce(params);
}

BENCHMARK(BenchmarkBasicModel);

static void BenchmarkBasicModelLargeSize(benchmark::State& state) {
    casbin::Enforcer e(basic_model_path, "", false);

    size_t actors_count = 10;
    size_t resources_count = 100;
    size_t resource_actor_rate = resources_count / actors_count;
    size_t actions_count = 5;

    for (size_t j = 0; j < resources_count; ++j)
        for (size_t k = 0; k < actions_count; ++k)
            e.AddPolicy({
                "actor" + std::to_string(j % resource_actor_rate),
                "resource" + std::to_string(j),
                "action" + std::to_string(k)
            });

    casbin::DataList params = {
	"actor" + std::to_string(actors_count - 1),
	"resource" + std::to_string(resources_count - 1),
	"action" + std::to_string(actions_count - 1)
    };
    for (auto _ : state) e.Enforce(params);
}

BENCHMARK(BenchmarkBasicModelLargeSize);

static void BenchmarkRBACModel(benchmark::State& state) {
    casbin::Enforcer e(rbac_model_path, rbac_policy_path, false);

    casbin::DataList params = {"alice", "data2", "read"};

    for (auto _ : state) e.Enforce(params);
}

BENCHMARK(BenchmarkRBACModel);

static void BenchmarkRBACModelSizesSmall(benchmark::State& state) {
    int num_roles = 100, num_resources = 10, num_users = 1000;

    casbin::Enforcer e(rbac_model_path, "", false);

    for (int i = 0; i < num_roles; ++i)
        e.AddPolicy({
            "group-has-a-very-long-name-" + std::to_string(i),
            "data-has-a-very-long-name-" + std::to_string(i % num_resources),
            "read"
        });

    for (int i = 0; i < num_users; ++i)
        e.AddGroupingPolicy({
            "user-has-a-very-long-name-" + std::to_string(i),
            "group-has-a-very-long-name-" + std::to_string(i % num_roles)
        });

    int itr = 0;
    for (auto _ : state)
        e.Enforce({
            "user-has-a-very-long-name-" + std::to_string(itr % num_users),
            "data-has-a-very-long-name-" + std::to_string(itr % num_resources),
            "read"
        }), ++itr;
}

BENCHMARK(BenchmarkRBACModelSizesSmall);

static void BenchmarkRBACModelSmall(benchmark::State& state) {
    casbin::Enforcer e(rbac_model_path);

    // 100 roles, 10 resources.
    for (int i = 0; i < 100; ++i) e.AddPolicy({"group" + std::to_string(i), "data" + std::to_string(i / 10), "read"});

    // 1000 users.
    for (int i = 0; i < 1000; ++i) e.AddGroupingPolicy({"user" + std::to_string(i), "group" + std::to_string(i / 10)});

    casbin::DataList params = {"user501", "data9", "read"};
    for (auto _ : state) e.Enforce(params);
}

BENCHMARK(BenchmarkRBACModelSmall);

static void BenchmarkRBACModelWithResourceRoles(benchmark::State& state) {
    casbin::Enforcer e(rbac_with_resource_roles_model_path, rbac_with_resource_roles_policy_path, false);

    casbin::DataList params = {"alice", "data1", "read"};
    for (auto _ : state) e.Enforce(params);
}

BENCHMARK(BenchmarkRBACModelWithResourceRoles);

static void BenchmarkRBACModelWithDomains(benchmark::State& state) {
    casbin::Enforcer e(rbac_with_domains_model_path, rbac_with_domains_policy_path, false);
    casbin::DataList params = {"alice", "domain1", "data1", "read"};

    for (auto _ : state) e.Enforce(params);
}

BENCHMARK(BenchmarkRBACModelWithDomains);

// ------ TODO ------
// static void BenchmarkABACModel(benchmark::State& state) {
//     casbin::Enforcer e("examples/abac_model.conf")
//     data1 := newTestResource("data1", "alice")

//     for(auto _ : state) {
//         _, _ = e.Enforce("alice", data1, "read")
//     }
// }

// ------ TODO ------
// static void BenchmarkABACRuleModel(benchmark::State& state) {
//     casbin::Enforcer e("examples/abac_model.conf")
//     data1 := newTestResource("data1", "alice")

//     for(auto _ : state) {
//         _, _ = e.Enforce("alice", data1, "read")
//     }
// }


static void BenchmarkKeyMatchModel(benchmark::State& state) {
    casbin::Enforcer e(keymatch_model_path, keymatch_policy_path, false);
    casbin::DataList params = {"alice", "/alice_data/resource1", "GET"};

    for (auto _ : state) e.Enforce(params);
}

BENCHMARK(BenchmarkKeyMatchModel);

static void BenchmarkRBACModelWithDeny(benchmark::State& state) {
    casbin::Enforcer e(rbac_with_deny_model_path, rbac_with_deny_policy_path, false);
    casbin::DataList params = {"alice", "data1", "read"};

    for (auto _ : state) e.Enforce(params);
}

BENCHMARK(BenchmarkRBACModelWithDeny);

static void BenchmarkPriorityModel(benchmark::State& state) {
    casbin::Enforcer e(priority_model_path, priority_policy_path, false);
    casbin::DataList params = {"alice", "data1", "read"};

    for (auto _ : state) e.Enforce(params);
}

BENCHMARK(BenchmarkPriorityModel);
