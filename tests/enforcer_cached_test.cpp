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

/* This is a test file showcasing the workflow of casbin::CachedEnforcer */

#include <casbin/casbin.h>
#include <gtest/gtest.h>

#include "config_path.h"

namespace {

TEST(TestEnforcerCached, TestCache) {
    casbin::CachedEnforcer e(basic_model_path, basic_policy_path);
    ASSERT_EQ(e.Enforce({"alice", "data1", "read"}), true);
    ASSERT_EQ(e.Enforce({"alice", "data1", "write"}), false);
    ASSERT_EQ(e.Enforce({"alice", "data2", "read"}), false);
    ASSERT_EQ(e.Enforce({"alice", "data2", "write"}), false);

    // A policy change drops the cached decisions.
    e.RemovePolicy({"alice", "data1", "read"});
    ASSERT_EQ(e.Enforce({"alice", "data1", "read"}), false);
    ASSERT_EQ(e.Enforce({"alice", "data1", "write"}), false);
    ASSERT_EQ(e.Enforce({"alice", "data2", "read"}), false);
    ASSERT_EQ(e.Enforce({"alice", "data2", "write"}), false);

    e.InvalidateCache();
    ASSERT_EQ(e.Enforce({"alice", "data1", "read"}), false);
    ASSERT_EQ(e.Enforce({"alice", "data1", "write"}), false);
    ASSERT_EQ(e.Enforce({"alice", "data2", "read"}), false);
    ASSERT_EQ(e.Enforce({"alice", "data2", "write"}), false);
}

TEST(TestEnforcerCached, TestCacheInvalidatedOnPolicyChange) {
    casbin::CachedEnforcer e(rbac_model_path, rbac_policy_path);
    ASSERT_TRUE(e.Enforce({"alice", "data2", "read"}));

    e.RemoveGroupingPolicy({"alice", "data2_admin"});
    ASSERT_FALSE(e.Enforce({"alice", "data2", "read"}));

    e.AddGroupingPolicy({"alice", "data2_admin"});
    ASSERT_TRUE(e.Enforce({"alice", "data2", "read"}));

    e.DeleteRoleForUser("alice", "data2_admin");
    ASSERT_FALSE(e.Enforce({"alice", "data2", "read"}));

    e.AddPolicy({"alice", "data2", "read"});
    ASSERT_TRUE(e.Enforce({"alice", "data2", "read"}));

    e.UpdatePolicy({"alice", "data2", "read"}, {"alice", "data3", "read"});
    ASSERT_FALSE(e.Enforce({"alice", "data2", "read"}));

    e.ClearPolicy();
    ASSERT_FALSE(e.Enforce({"alice", "data3", "read"}));

    e.LoadPolicy();
    ASSERT_TRUE(e.Enforce({"alice", "data1", "read"}));
    e.RemoveFilteredPolicy(0, {"alice"});
    ASSERT_FALSE(e.Enforce({"alice", "data1", "read"}));
}

TEST(TestEnforcerCached, TestCacheKeyCollision) {
    casbin::CachedEnforcer e(basic_model_path, basic_policy_path);
    e.AddPolicy({"alice", "data1$$read", "x"});
    ASSERT_TRUE(e.Enforce({"alice", "data1$$read", "x"}));
    ASSERT_FALSE(e.Enforce({"alice", "data1", "read$$x"}));
    ASSERT_TRUE(e.Enforce(casbin::DataVector{"alice", "data1", "read"}));
    ASSERT_FALSE(e.Enforce(casbin::DataVector{"alice", "data1", "write"}));
}

TEST(TestEnforcerCached, TestCacheWithJsonData) {
    using json = nlohmann::json;
    casbin::CachedEnforcer e(abac_rule_model_path, abac_rule_policy_path);

    casbin::DataMap params = {{"sub", std::make_shared<json>(json{{"Name", "alice"}, {"Age", 30}})}, {"obj", "/data1"}, {"act", "read"}};
    ASSERT_TRUE(e.Enforce(params));

    params = {{"sub", std::make_shared<json>(json{{"Name", "bob"}, {"Age", 16}})}, {"obj", "/data1"}, {"act", "read"}};
    ASSERT_FALSE(e.Enforce(params));
}

} // namespace
