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

/* This is an intensive test file for benchmarking the performance of casbin's Management API */

#include <benchmark/benchmark.h>
#include <casbin/casbin.h>

#include <random>

#include "config_path.h"

static std::random_device generator;
static std::uniform_int_distribution<int> dist_100(1, 100);
static std::uniform_int_distribution<int> dist_1000(1, 1000);
static std::uniform_int_distribution<int> dist_10000(1, 10000);
static std::vector<std::string> params(3);

static inline int GetRandom100() { return dist_100(generator); }

static inline int GetRandom1000() { return dist_1000(generator); }

static inline int GetRandom10000() { return dist_10000(generator); }

static void BenchmarkHasPolicyMedium(benchmark::State& state) {
    casbin::Enforcer e(basic_model_path);

    // 1000 roles, 100 resources.
    // PoliciesValues p_policies(1000);
    for (int i = 0; i < 1000; ++i) params = {"user" + std::to_string(i), "data" + std::to_string(i / 10), "read"}, e.AddPolicy(params);
    // e.AddPolicies(p_policies);
    for (auto _ : state) params = {"user" + std::to_string(GetRandom1000()), "data" + std::to_string(GetRandom1000() / 10), "read"}, e.HasPolicy(params);
}

BENCHMARK(BenchmarkHasPolicyMedium);

static void BenchmarkHasPolicyLarge(benchmark::State& state) {
    casbin::Enforcer e(basic_model_path);

    // 10000 roles, 1000 resources.
    for (int i = 0; i < 10000; i++) params = {"user" + std::to_string(i), "data" + std::to_string(i / 10), "read"}, e.AddPolicy(params);

    for (auto _ : state) {
        params = {"user" + std::to_string(GetRandom10000()), "data" + std::to_string(GetRandom10000() / 10), "read"}, e.HasPolicy(params);
    }
}

BENCHMARK(BenchmarkHasPolicyLarge);

static void BenchmarkAddPolicyMedium(benchmark::State& state) {
    casbin::Enforcer e(basic_model_path);

    // 1000 roles, 100 resources.
    for (int i = 0; i < 1000; ++i) params = {"user" + std::to_string(i), "data" + std::to_string(i / 10), "read"}, e.AddPolicy(params);
    // _, err := e.AddPolicies(pPolicies)

    for (auto _ : state) {
        params = {"user" + std::to_string(GetRandom1000() + 1000), "data" + std::to_string((GetRandom1000() + 1000) / 10), "read"}, e.AddPolicy(params);
    }
}

BENCHMARK(BenchmarkAddPolicyMedium);

static void BenchmarkAddPolicyLarge(benchmark::State& state) {
    casbin::Enforcer e(basic_model_path);

    // 10000 roles, 1000 resources.
    for (int i = 0; i < 10000; ++i) params = {"user" + std::to_string(i), "data" + std::to_string(i / 10), "read"}, e.AddPolicy(params);

    for (auto _ : state) {
        params = {"user" + std::to_string(GetRandom10000() + 10000), "data" + std::to_string((GetRandom10000() + 10000) / 10), "read"}, e.AddPolicy(params);
    }
}

BENCHMARK(BenchmarkAddPolicyLarge);

static void BenchmarkRemovePolicyMedium(benchmark::State& state) {
    casbin::Enforcer e(basic_model_path);

    // 1000 roles, 100 resources.
    for (int i = 0; i < 1000; ++i) params = {"user" + std::to_string(i), "data" + std::to_string(i / 10), "read"}, e.AddPolicy(params);

    for (auto _ : state) params = {"user" + std::to_string(GetRandom1000()), "data" + std::to_string(GetRandom1000() / 10), "read"}, e.RemovePolicy(params);
}

BENCHMARK(BenchmarkRemovePolicyMedium);

static void BenchmarkRemovePolicyLarge(benchmark::State& state) {
    casbin::Enforcer e(basic_model_path);

    // 10000 roles, 1000 resources.
    for (int i = 0; i < 10000; ++i) params = {"user" + std::to_string(i), "data" + std::to_string(i / 10), "read"}, e.AddPolicy(params);

    for (auto _ : state) params = {"user" + std::to_string(GetRandom10000()), "data" + std::to_string(GetRandom1000()), "read"}, e.RemovePolicy(params);
}

BENCHMARK(BenchmarkRemovePolicyLarge);