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

/* This is an intensive test file for benchmarking the performance of casbin::Model */

#include <benchmark/benchmark.h>
#include <casbin/casbin.h>

#include "config_path.h"


static void _BenchmarkRBACModelSizes(benchmark::State& state, int num_roles, int num_resources, int num_users) {

    casbin::Enforcer e(rbac_model_path, "", false);

    for (int i = 0; i < num_roles; ++i) e.AddPolicy({"group-has-a-very-long-name-" + std::to_string(i), "data-has-a-very-long-name-" + std::to_string(i % num_resources), "read"});

    for (int i = 0; i < num_users; ++i) {
        e.AddGroupingPolicy({"user-has-a-very-long-name-" + std::to_string(i), "group-has-a-very-long-name-" + std::to_string(i % num_roles)});
    }

    int num_request = 17;
    std::vector<casbin::DataList> requests(num_request);

    for (int i = 0; i < num_request; ++i) {
        int id_user = num_users / num_request * i,
            id_role = id_user / num_roles,
            id_resource = id_role % num_resources;
        if (i&2 == 0) 
            id_resource = (id_resource + 1) % num_resources;

        requests[i] = {"user-has-a-very-long-name-" + std::to_string(id_user), "data-has-a-very-long-name-" + std::to_string(id_resource), "read"};
    }

    for (auto _ : state) 
        for (auto& req: requests) 
            e.Enforce(req);
}

static void BenchmarkRBACModelSizesMedium(benchmark::State& state) {
    _BenchmarkRBACModelSizes(state, 1000, 100, 10000);
}

BENCHMARK(BenchmarkRBACModelSizesMedium);

static void BenchmarkRBACModelSizesLarge(benchmark::State& state) {
    _BenchmarkRBACModelSizes(state, 10000, 1000, 100000);
}

BENCHMARK(BenchmarkRBACModelSizesLarge);


static const PoliciesValues s_policy = {{"alice", "data1", "read"}, {"bob", "data2", "write"}};
static void BenchmarkRBACModelMedium(benchmark::State& state) {
    casbin::Enforcer e(rbac_model_path);

    // 1000 roles, 100 resources.
    for (int i = 0; i < 1000; ++i) e.AddPolicy({"group" + std::to_string(i), "data" + std::to_string(i / 10), "read"});

    // 10000 users.
    for (int i = 0; i < 10000; ++i) e.AddGroupingPolicy({"user" + std::to_string(i), "group" + std::to_string(i / 10)});

    casbin::DataList params = {"user5001", "data99", "read"};
    for (auto _ : state) e.Enforce(params);
}

BENCHMARK(BenchmarkRBACModelMedium);

static void BenchmarkRBACModelLarge(benchmark::State& state) {
    casbin::Enforcer e(rbac_model_path);

    // 10000 roles, 1000 resources.
    for (int i = 0; i < 10000; ++i) e.AddPolicy({"group" + std::to_string(i), "data" + std::to_string(i / 10), "read"});

    // 100000 users.
    for (int i = 0; i < 100000; i++) e.AddGroupingPolicy({"user" + std::to_string(i), "group" + std::to_string(i / 10)});

    casbin::DataList params = {"user50001", "data999", "read"};

    for (auto _ : state) e.Enforce(params);
}

BENCHMARK(BenchmarkRBACModelLarge);


 static void BenchmarkRBACModelWithDomainPatternLarge(benchmark::State& state) {
     casbin::Enforcer e(rbac_with_pattern_large_scale_model_path, rbac_with_pattern_large_scale_policy_path);
    
     e.AddNamedMatchingFunc("g", "", casbin::KeyMatch4);

     casbin::DataList params = {"staffUser1001", "/orgs/1/sites/site001", "App001.Module001.Action1001"};

     for (auto _ : state) e.Enforce(params);
 }

 BENCHMARK(BenchmarkRBACModelWithDomainPatternLarge);


