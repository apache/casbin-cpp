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

/* This is a test file for testing built in functions in casbin */

#include <casbin/casbin.h>
#include <gtest/gtest.h>

#include "config_path.h"

namespace {
std::string global_sub;
std::string global_obj;
std::string global_act;
std::string global_domain;

template <typename T>
std::shared_ptr<casbin::IEvaluator> InitializeParams(const std::string& sub, const std::string& obj, const std::string& act) {
    auto evaluator = std::make_shared<T>();
    evaluator->InitialObject("r");

    // Because of "Short String Optimization", these strings's data is in stack.
    // For MSVC compiler, when this stack frame return, these memory will can't access.
    // So we need keep this memory accessiable.
    global_sub = sub;
    global_obj = obj;
    global_act = act;

    evaluator->PushObjectString("r", "sub", global_sub);
    evaluator->PushObjectString("r", "obj", global_obj);
    evaluator->PushObjectString("r", "act", global_act);

    return evaluator;
}

template <typename T>
std::shared_ptr<casbin::IEvaluator> InitializeParamsWithoutUsers(const std::string& obj, const std::string& act) {
    auto evaluator = std::make_shared<T>();
    evaluator->InitialObject("r");

    global_obj = obj;
    global_act = act;
    evaluator->PushObjectString("r", "obj", global_obj);
    evaluator->PushObjectString("r", "act", global_act);
    return evaluator;
}

template <typename T>
std::shared_ptr<casbin::IEvaluator> InitializeParamsWithoutResources(const std::string& sub, const std::string& act) {
    auto evaluator = std::make_shared<T>();
    evaluator->InitialObject("r");

    global_sub = sub;
    global_act = act;
    evaluator->PushObjectString("r", "sub", global_sub);
    evaluator->PushObjectString("r", "act", global_act);
    return evaluator;
}

template <typename T>
std::shared_ptr<casbin::IEvaluator> InitializeParamsWithDomains(const std::string& sub, const std::string& domain, const std::string& obj, const std::string& act) {
    auto evaluator = std::make_shared<T>();
    evaluator->InitialObject("r");

    global_sub = sub;
    global_obj = obj;
    global_act = act;
    global_domain = domain;

    evaluator->PushObjectString("r", "sub", global_sub);
    evaluator->PushObjectString("r", "dom", global_domain);
    evaluator->PushObjectString("r", "obj", global_obj);
    evaluator->PushObjectString("r", "act", global_act);
    return evaluator;
}

// casbin::Scope InitializeParamsWithJson(std::shared_ptr<nlohmann::json> sub, std::string obj, std::string act) {
//     casbin::Scope scope = casbin::InitializeScope();
//     casbin::PushObject(scope, "r");

//     casbin::PushStringPropToObject(scope, "r", obj, "obj");
//     casbin::PushStringPropToObject(scope, "r", act, "act");

//     casbin::PushObject(scope, "sub");
//     casbin::PushObjectPropFromJson(scope, *sub, "sub");
//     casbin::PushObjectPropToObject(scope, "r", "sub");

//     return scope;
// }

// void TestEnforce(casbin::Enforcer& e, casbin::Scope& scope, bool res) {
//     auto evaluator = std::make_shared<casbin::DuktapeEvaluator>(scope);
//     ASSERT_EQ(res, e.Enforce(evaluator));
// }

void TestEnforce(casbin::Enforcer& e, std::shared_ptr<casbin::IEvaluator> evaluator, bool res) { ASSERT_EQ(res, e.Enforce(evaluator)); }

TEST(TestModelEnforcer, TestBasicModel) {
    casbin::Enforcer e(basic_model_path, basic_policy_path);

    std::shared_ptr<casbin::IEvaluator> evaluator;

    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data1", "read");
    TestEnforce(e, evaluator, true);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data1", "write");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data2", "read");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data2", "write");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data1", "read");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data1", "write");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data2", "read");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data2", "write");
    TestEnforce(e, evaluator, true);
}

TEST(TestModelEnforcer, TestBasicModelWithoutSpaces) {
    casbin::Enforcer e(basic_model_without_spaces_path, basic_policy_path);

    std::shared_ptr<casbin::IEvaluator> evaluator;

    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data1", "read");
    TestEnforce(e, evaluator, true);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data1", "write");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data2", "read");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data2", "write");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data1", "read");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data1", "write");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data2", "read");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data2", "write");
    TestEnforce(e, evaluator, true);
}

TEST(TestModelEnforcer, TestBasicModelNoPolicy) {
    casbin::Enforcer e(basic_model_path);

    std::shared_ptr<casbin::IEvaluator> evaluator;

    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data1", "read");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data1", "write");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data2", "read");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data2", "write");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data1", "read");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data1", "write");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data2", "read");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data2", "write");
    TestEnforce(e, evaluator, false);
}

TEST(TestModelEnforcer, TestBasicModelWithRoot) {
    casbin::Enforcer e(basic_with_root_model_path, basic_policy_path);

    std::shared_ptr<casbin::IEvaluator> evaluator;

    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data1", "read");
    TestEnforce(e, evaluator, true);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data1", "write");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data2", "read");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data2", "write");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data1", "read");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data1", "write");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data2", "read");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data2", "write");
    TestEnforce(e, evaluator, true);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("root", "data1", "read");
    TestEnforce(e, evaluator, true);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("root", "data1", "write");
    TestEnforce(e, evaluator, true);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("root", "data2", "read");
    TestEnforce(e, evaluator, true);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("root", "data2", "write");
    TestEnforce(e, evaluator, true);
}

TEST(TestModelEnforcer, TestBasicModelWithRootNoPolicy) {
    casbin::Enforcer e(basic_with_root_model_path);

    std::shared_ptr<casbin::IEvaluator> evaluator;

    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data1", "read");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data1", "write");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data2", "read");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data2", "write");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data1", "read");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data1", "write");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data2", "read");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data2", "write");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("root", "data1", "read");
    TestEnforce(e, evaluator, true);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("root", "data1", "write");
    TestEnforce(e, evaluator, true);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("root", "data2", "read");
    TestEnforce(e, evaluator, true);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("root", "data2", "write");
    TestEnforce(e, evaluator, true);
}

TEST(TestModelEnforcer, TestBasicModelWithoutUsers) {
    casbin::Enforcer e(basic_without_users_model_path, basic_without_users_policy_path);

    auto evaluator = InitializeParamsWithoutUsers<casbin::ExprtkEvaluator>("data1", "read");
    TestEnforce(e, evaluator, true);
    evaluator = InitializeParamsWithoutUsers<casbin::ExprtkEvaluator>("data1", "write");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParamsWithoutUsers<casbin::ExprtkEvaluator>("data2", "read");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParamsWithoutUsers<casbin::ExprtkEvaluator>("data2", "write");
    TestEnforce(e, evaluator, true);
}

TEST(TestModelEnforcer, TestBasicModelWithoutResources) {
    casbin::Enforcer e(basic_without_resources_model_path, basic_without_resources_policy_path);

    auto evaluator = InitializeParamsWithoutResources<casbin::ExprtkEvaluator>("alice", "read");
    TestEnforce(e, evaluator, true);
    evaluator = InitializeParamsWithoutResources<casbin::ExprtkEvaluator>("alice", "write");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParamsWithoutResources<casbin::ExprtkEvaluator>("bob", "read");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParamsWithoutResources<casbin::ExprtkEvaluator>("bob", "write");
    TestEnforce(e, evaluator, true);
}

TEST(TestModelEnforcer, TestRBACModel) {
    casbin::Enforcer e(rbac_model_path, rbac_policy_path);

    std::shared_ptr<casbin::IEvaluator> evaluator;

    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data1", "read");
    TestEnforce(e, evaluator, true);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data1", "write");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data2", "read");
    TestEnforce(e, evaluator, true);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data2", "write");
    TestEnforce(e, evaluator, true);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data1", "read");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data1", "write");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data2", "read");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data2", "write");
    TestEnforce(e, evaluator, true);
}

TEST(TestModelEnforcer, TestRBACModelWithResourceRoles) {
    casbin::Enforcer e(rbac_with_resource_roles_model_path, rbac_with_resource_roles_policy_path);

    std::shared_ptr<casbin::IEvaluator> evaluator;

    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data1", "read");
    TestEnforce(e, evaluator, true);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data1", "write");
    TestEnforce(e, evaluator, true);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data2", "read");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data2", "write");
    TestEnforce(e, evaluator, true);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data1", "read");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data1", "write");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data2", "read");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data2", "write");
    TestEnforce(e, evaluator, true);
}

TEST(TestModelEnforcer, TestRBACModelWithDomains) {
    casbin::Enforcer e(rbac_with_domains_model_path, rbac_with_domains_policy_path);

    auto evaluator = InitializeParamsWithDomains<casbin::ExprtkEvaluator>("alice", "domain1", "data1", "read");
    TestEnforce(e, evaluator, true);
    evaluator = InitializeParamsWithDomains<casbin::ExprtkEvaluator>("alice", "domain1", "data1", "write");
    TestEnforce(e, evaluator, true);
    evaluator = InitializeParamsWithDomains<casbin::ExprtkEvaluator>("alice", "domain1", "data2", "read");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParamsWithDomains<casbin::ExprtkEvaluator>("alice", "domain1", "data2", "write");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParamsWithDomains<casbin::ExprtkEvaluator>("bob", "domain2", "data1", "read");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParamsWithDomains<casbin::ExprtkEvaluator>("bob", "domain2", "data1", "write");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParamsWithDomains<casbin::ExprtkEvaluator>("bob", "domain2", "data2", "read");
    TestEnforce(e, evaluator, true);
    evaluator = InitializeParamsWithDomains<casbin::ExprtkEvaluator>("bob", "domain2", "data2", "write");
    TestEnforce(e, evaluator, true);
}

TEST(TestModelEnforcer, TestRBACModelWithDomainsAtRuntime) {
    casbin::Enforcer e(rbac_with_domains_model_path);

    std::vector<std::string> params{"admin", "domain1", "data1", "read"};
    e.AddPolicy(params);
    params = std::vector<std::string>{"admin", "domain1", "data1", "write"};
    e.AddPolicy(params);
    params = std::vector<std::string>{"admin", "domain2", "data2", "read"};
    e.AddPolicy(params);
    params = std::vector<std::string>{"admin", "domain2", "data2", "write"};
    e.AddPolicy(params);

    params = std::vector<std::string>{"alice", "admin", "domain1"};
    e.AddGroupingPolicy(params);
    params = std::vector<std::string>{"bob", "admin", "domain2"};
    e.AddGroupingPolicy(params);

    auto evaluator = InitializeParamsWithDomains<casbin::ExprtkEvaluator>("alice", "domain1", "data1", "read");
    TestEnforce(e, evaluator, true);
    evaluator = InitializeParamsWithDomains<casbin::ExprtkEvaluator>("alice", "domain1", "data1", "write");
    TestEnforce(e, evaluator, true);
    evaluator = InitializeParamsWithDomains<casbin::ExprtkEvaluator>("alice", "domain1", "data2", "read");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParamsWithDomains<casbin::ExprtkEvaluator>("alice", "domain1", "data2", "write");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParamsWithDomains<casbin::ExprtkEvaluator>("bob", "domain2", "data1", "read");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParamsWithDomains<casbin::ExprtkEvaluator>("bob", "domain2", "data1", "write");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParamsWithDomains<casbin::ExprtkEvaluator>("bob", "domain2", "data2", "read");
    TestEnforce(e, evaluator, true);
    evaluator = InitializeParamsWithDomains<casbin::ExprtkEvaluator>("bob", "domain2", "data2", "write");
    TestEnforce(e, evaluator, true);

    // Remove all policy rules related to domain1 and data1.
    params = std::vector<std::string>{"domain1", "data1"};
    e.RemoveFilteredPolicy(1, params);

    evaluator = InitializeParamsWithDomains<casbin::ExprtkEvaluator>("alice", "domain1", "data1", "read");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParamsWithDomains<casbin::ExprtkEvaluator>("alice", "domain1", "data1", "write");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParamsWithDomains<casbin::ExprtkEvaluator>("alice", "domain1", "data2", "read");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParamsWithDomains<casbin::ExprtkEvaluator>("alice", "domain1", "data2", "read");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParamsWithDomains<casbin::ExprtkEvaluator>("bob", "domain2", "data1", "read");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParamsWithDomains<casbin::ExprtkEvaluator>("bob", "domain2", "data1", "write");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParamsWithDomains<casbin::ExprtkEvaluator>("bob", "domain2", "data2", "read");
    TestEnforce(e, evaluator, true);
    evaluator = InitializeParamsWithDomains<casbin::ExprtkEvaluator>("bob", "domain2", "data2", "write");
    TestEnforce(e, evaluator, true);

    // Remove the specified policy rule.
    params = std::vector<std::string>{"admin", "domain2", "data2", "read"};
    e.RemovePolicy(params);

    evaluator = InitializeParamsWithDomains<casbin::ExprtkEvaluator>("alice", "domain1", "data1", "read");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParamsWithDomains<casbin::ExprtkEvaluator>("alice", "domain1", "data1", "write");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParamsWithDomains<casbin::ExprtkEvaluator>("alice", "domain1", "data2", "read");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParamsWithDomains<casbin::ExprtkEvaluator>("alice", "domain1", "data2", "write");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParamsWithDomains<casbin::ExprtkEvaluator>("bob", "domain2", "data1", "read");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParamsWithDomains<casbin::ExprtkEvaluator>("bob", "domain2", "data1", "write");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParamsWithDomains<casbin::ExprtkEvaluator>("bob", "domain2", "data2", "read");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParamsWithDomains<casbin::ExprtkEvaluator>("bob", "domain2", "data2", "write");
    TestEnforce(e, evaluator, true);
}

TEST(TestModelEnforcer, TestRBACModelWithDomainsAtRuntimeMockAdapter) {
    std::shared_ptr<casbin::Adapter> adapter = std::make_shared<casbin::FileAdapter>(rbac_with_domains_policy_path);
    casbin::Enforcer e(rbac_with_domains_model_path, adapter);

    std::vector<std::string> params{"admin", "domain3", "data1", "read"};
    e.AddPolicy(params);
    params = std::vector<std::string>{"alice", "admin", "domain3"};
    e.AddGroupingPolicy(params);

    auto evaluator = InitializeParamsWithDomains<casbin::ExprtkEvaluator>("alice", "domain3", "data1", "read");
    TestEnforce(e, evaluator, true);

    evaluator = InitializeParamsWithDomains<casbin::ExprtkEvaluator>("alice", "domain1", "data1", "read");
    TestEnforce(e, evaluator, true);

    params = std::vector<std::string>{"domain1", "data1"};
    e.RemoveFilteredPolicy(1, params);

    evaluator = InitializeParamsWithDomains<casbin::ExprtkEvaluator>("alice", "domain1", "data1", "read");
    TestEnforce(e, evaluator, false);

    evaluator = InitializeParamsWithDomains<casbin::ExprtkEvaluator>("bob", "domain2", "data2", "read");
    TestEnforce(e, evaluator, true);
    params = std::vector<std::string>{"admin", "domain2", "data2", "read"};
    e.RemovePolicy(params);

    evaluator = InitializeParamsWithDomains<casbin::ExprtkEvaluator>("bob", "domain2", "data2", "read");
    TestEnforce(e, evaluator, false);
}

TEST(TestModelEnforcer, TestRBACModelWithDeny) {
    casbin::Enforcer e(rbac_with_deny_model_path, rbac_with_deny_policy_path);

    std::shared_ptr<casbin::IEvaluator> evaluator;

    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data1", "read");
    TestEnforce(e, evaluator, true);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data1", "write");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data2", "read");
    TestEnforce(e, evaluator, true);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data2", "write");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data1", "read");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data1", "write");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data2", "read");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data2", "write");
    TestEnforce(e, evaluator, true);
}

TEST(TestModelEnforcer, TestRBACModelWithOnlyDeny) {
    casbin::Enforcer e(rbac_with_not_deny_model_path, rbac_with_deny_policy_path);

    auto evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data2", "write");
    TestEnforce(e, evaluator, false);
}

TEST(TestModelEnforcer, TestRBACModelWithCustomData) {
    casbin::Enforcer e(rbac_model_path, rbac_policy_path);

    // You can add custom data to a grouping policy, Casbin will ignore it. It is only meaningful to the caller.
    // This feature can be used to store information like whether "bob" is an end user (so no subject will inherit "bob")
    // For Casbin, it is equivalent to: e.AddGroupingPolicy("bob", "data2_admin")
    std::vector<std::string> params{"bob", "data2_admin", "custom_data"};
    e.AddGroupingPolicy(params);

    auto evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data1", "read");
    TestEnforce(e, evaluator, true);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data1", "write");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data2", "read");
    TestEnforce(e, evaluator, true);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data2", "write");
    TestEnforce(e, evaluator, true);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data1", "read");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data1", "write");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data2", "read");
    TestEnforce(e, evaluator, true);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data2", "write");
    TestEnforce(e, evaluator, true);

    // You should also take the custom data as a parameter when deleting a grouping policy.
    // e.RemoveGroupingPolicy("bob", "data2_admin") won't work.
    // Or you can remove it by using RemoveFilteredGroupingPolicy().
    params = std::vector<std::string>{"bob", "data2_admin", "custom_data"};
    e.RemoveGroupingPolicy(params);

    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data1", "read");
    TestEnforce(e, evaluator, true);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data1", "write");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data2", "read");
    TestEnforce(e, evaluator, true);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data2", "write");
    TestEnforce(e, evaluator, true);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data1", "read");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data1", "write");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data2", "read");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data2", "write");
    TestEnforce(e, evaluator, true);
}

TEST(TestModelEnforcer, TestRBACModelWithPattern) {
    casbin::Enforcer e(rbac_with_pattern_model_path, rbac_with_pattern_policy_path);

    // Here's a little confusing: the matching function here is not the custom function used in matcher.
    // It is the matching function used by "g" (and "g2", "g3" if any..)
    // You can see in policy that: "g2, /book/:id, book_group", so in "g2()" function in the matcher, instead
    // of checking whether "/book/:id" equals the obj: "/book/1", it checks whether the pattern matches.
    // You can see it as normal RBAC: "/book/:id" == "/book/1" becomes KeyMatch2("/book/:id", "/book/1")
    e.AddNamedMatchingFunc("p", "", casbin::KeyMatch2);

    auto evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "/book/1", "GET");
    TestEnforce(e, evaluator, true);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "/book/2", "GET");
    TestEnforce(e, evaluator, true);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "/pen/1", "GET");
    TestEnforce(e, evaluator, true);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "/pen/2", "GET");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "/book/1", "GET");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "/book/2", "GET");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "/pen/1", "GET");
    TestEnforce(e, evaluator, true);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "/pen/2", "GET");
    TestEnforce(e, evaluator, true);

    // AddMatchingFunc() is actually setting a function because only one function is allowed,
    // so when we set "KeyMatch3", we are actually replacing "KeyMatch2" with "KeyMatch3".
    e.AddNamedMatchingFunc("p", "", casbin::KeyMatch3);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "/book2/1", "GET");
    TestEnforce(e, evaluator, true);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "/book2/2", "GET");
    TestEnforce(e, evaluator, true);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "/pen2/1", "GET");
    TestEnforce(e, evaluator, true);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "/pen2/2", "GET");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "/book2/1", "GET");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "/book2/2", "GET");
    TestEnforce(e, evaluator, false);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "/pen2/1", "GET");
    TestEnforce(e, evaluator, true);
    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "/pen2/2", "GET");
    TestEnforce(e, evaluator, true);
}

} // namespace
