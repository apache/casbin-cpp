/*
 * Copyright 2021 The casbin Authors. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * This is a test file showcasing the workflow of casbin::Enforcer
 */

#include <casbin/casbin.h>
#include <casbin/persist/string_adapter.h>
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

TEST(TestEnforcer, TestFourParams) {
    casbin::Enforcer e(rbac_with_domains_model_path, rbac_with_domains_policy_path);

    ASSERT_EQ(e.Enforce({"alice", "domain1", "data1", "read"}), true);
    ASSERT_EQ(e.Enforce({"alice", "domain1", "data1", "write"}), true);
    ASSERT_EQ(e.Enforce({"alice", "domain1", "data2", "read"}), false);
    ASSERT_EQ(e.Enforce({"alice", "domain1", "data2", "write"}), false);
    ASSERT_EQ(e.Enforce({"bob", "domain2", "data1", "read"}), false);
    ASSERT_EQ(e.Enforce({"bob", "domain2", "data1", "write"}), false);
    ASSERT_EQ(e.Enforce({"bob", "domain2", "data2", "read"}), true);
    ASSERT_EQ(e.Enforce({"bob", "domain2", "data2", "write"}), true);
}

TEST(TestEnforcer, TestThreeParams) {
    casbin::Enforcer e(basic_model_without_spaces_path, basic_policy_path);

    ASSERT_EQ(e.Enforce({"alice", "data1", "read"}), true);
    ASSERT_EQ(e.Enforce({"alice", "data1", "write"}), false);
    ASSERT_EQ(e.Enforce({"alice", "data2", "read"}), false);
    ASSERT_EQ(e.Enforce({"alice", "data2", "write"}), false);
    ASSERT_EQ(e.Enforce({"bob", "data1", "read"}), false);
    ASSERT_EQ(e.Enforce({"bob", "data1", "write"}), false);
    ASSERT_EQ(e.Enforce({"bob", "data2", "read"}), false);
    ASSERT_EQ(e.Enforce({"bob", "data2", "write"}), true);
}

TEST(TestEnforcer, TestQuotedPolicy) {
    auto adapter = std::make_shared<casbin::StringAdapter>("p, admin, /, GET\np,    \"admin\",  /,  POST\n\"p\", \"admin\", \"/a,b\", PUT\np, \"say \"\"hi\"\"\", /, GET");
    casbin::Enforcer e(basic_model_path, adapter);

    ASSERT_EQ(e.Enforce({"admin", "/", "GET"}), true);
    ASSERT_EQ(e.Enforce({"admin", "/", "POST"}), true);
    ASSERT_EQ(e.Enforce({"admin", "/a,b", "PUT"}), true);
    ASSERT_EQ(e.Enforce({"say \"hi\"", "/", "GET"}), true);
    ASSERT_EQ(e.Enforce({"\"admin\"", "/", "POST"}), false);
}

TEST(TestEnforcer, TestVectorParams) {
    casbin::Enforcer e(basic_model_without_spaces_path, basic_policy_path);

    ASSERT_EQ(e.Enforce({"alice", "data1", "read"}), true);
    ASSERT_EQ(e.Enforce({"alice", "data1", "write"}), false);
    ASSERT_EQ(e.Enforce({"alice", "data2", "read"}), false);
    ASSERT_EQ(e.Enforce({"alice", "data2", "write"}), false);
    ASSERT_EQ(e.Enforce({"bob", "data1", "read"}), false);
    ASSERT_EQ(e.Enforce({"bob", "data1", "write"}), false);
    ASSERT_EQ(e.Enforce({"bob", "data2", "read"}), false);
    ASSERT_EQ(e.Enforce({"bob", "data2", "write"}), true);
}

TEST(TestEnforcer, TestMapParams) {
    casbin::Enforcer e(basic_model_without_spaces_path, basic_policy_path);

    casbin::DataMap params = {{"sub", "alice"}, {"obj", "data1"}, {"act", "read"}};
    ASSERT_EQ(e.Enforce(params), true);

    params = {{"sub", "alice"}, {"obj", "data1"}, {"act", "write"}};
    ASSERT_EQ(e.Enforce(params), false);

    params = {{"sub", "alice"}, {"obj", "data2"}, {"act", "read"}};
    ASSERT_EQ(e.Enforce(params), false);

    params = {{"sub", "alice"}, {"obj", "data2"}, {"act", "write"}};
    ASSERT_EQ(e.Enforce(params), false);

    params = {{"sub", "bob"}, {"obj", "data1"}, {"act", "read"}};
    ASSERT_EQ(e.Enforce(params), false);

    params = {{"sub", "bob"}, {"obj", "data1"}, {"act", "write"}};
    ASSERT_EQ(e.Enforce(params), false);

    params = {{"sub", "bob"}, {"obj", "data2"}, {"act", "read"}};
    ASSERT_EQ(e.Enforce(params), false);

    params = {{"sub", "bob"}, {"obj", "data2"}, {"act", "write"}};
    ASSERT_EQ(e.Enforce(params), true);
}

TEST(TestEnforcer, TestJsonData) {
    using json = nlohmann::json;
    casbin::Enforcer e(abac_rule_model_path, abac_rule_policy_path);

    // Test with JSON object containing Age property
    // Policy: p, r.sub.Age > 18, /data1, read
    auto sub_json_adult = std::make_shared<json>(json{
        {"Name", "alice"},
        {"Age", 30}
    });

    casbin::DataMap params = {
        {"sub", sub_json_adult},
        {"obj", "/data1"},
        {"act", "read"}
    };

    // Should be allowed: Age 30 > 18
    ASSERT_EQ(e.Enforce(params), true);

    // Test with minor (Age < 18)
    auto sub_json_minor = std::make_shared<json>(json{
        {"Name", "bob"},
        {"Age", 16}
    });

    params = {
        {"sub", sub_json_minor},
        {"obj", "/data1"},
        {"act", "read"}
    };

    // Should be denied: Age 16 < 18
    ASSERT_EQ(e.Enforce(params), false);

    // Test policy: p, r.sub.Age < 60, /data2, write
    auto sub_json_young = std::make_shared<json>(json{
        {"Name", "charlie"},
        {"Age", 45}
    });

    params = {
        {"sub", sub_json_young},
        {"obj", "/data2"},
        {"act", "write"}
    };

    // Should be allowed: Age 45 < 60
    ASSERT_EQ(e.Enforce(params), true);

    // Test with senior (Age >= 60)
    auto sub_json_senior = std::make_shared<json>(json{
        {"Name", "dave"},
        {"Age", 65}
    });

    params = {
        {"sub", sub_json_senior},
        {"obj", "/data2"},
        {"act", "write"}
    };

    // Should be denied: Age 65 >= 60
    ASSERT_EQ(e.Enforce(params), false);
}

TEST(TestEnforcer, TestComplexJsonData) {
    using json = nlohmann::json;
    
    // Create a custom model and policy for testing complex JSON structures
    // similar to the issue example
    casbin::Enforcer e(abac_rule_model_path, abac_rule_policy_path);

    // Test with complex nested JSON object like in the issue
    auto complex_request = std::make_shared<json>(json{
        {"ID", "zk"},
        {"proxy", "vpn"},
        {"Department", "nlp"},
        {"month", "Jan"},
        {"week", "Mon"},
        {"time", "morning"},
        {"Longitude", 123},
        {"Latitude", 456},
        {"Altitude", 789},
        {"OS", "HarmonyOS"},
        {"CPU", "XeonPlatinum8480+"},
        {"NetworkType", "WLan"},
        {"ProtocolType", "Bluetooth"},
        {"EncryptionType", "3DES"},
        {"SecurityProtocol", "HTTPS"},
        {"Age", 25}  // For testing with existing policy
    });

    casbin::DataMap params = {
        {"sub", complex_request},
        {"obj", "/data1"},
        {"act", "read"}
    };

    // Should work with complex JSON - Age 25 > 18
    ASSERT_EQ(e.Enforce(params), true);

    // Test with object that also contains nested objects
    auto obj_json = std::make_shared<json>(json{
        {"SecurityLevel", 3},
        {"Source", "ISS"},
        {"DistributionMethod", "C"}
    });

    params = {
        {"sub", complex_request},
        {"obj", obj_json},
        {"act", "read"}
    };

    // This should not crash even with JSON in multiple parameters
    ASSERT_NO_THROW(e.Enforce(params));
}

template <typename T>
void TestEnforceEx(casbin::Enforcer& e, T&& params, const bool expect_result, const std::vector<std::string>& expect_explain) {
    std::vector<std::string> actual_explain;
    ASSERT_EQ(e.EnforceEx(params, actual_explain), expect_result);
    ASSERT_EQ(actual_explain, expect_explain);
}

TEST(TestEnforcerEx, TestEvaluatorParams) {
    // BASIC_MODEL_WITHOUT_SPACES
    casbin::Enforcer e(basic_model_without_spaces_path, basic_policy_path);
    std::shared_ptr<casbin::IEvaluator> evaluator;

    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data1", "read");
    TestEnforceEx(e, evaluator, true, {"alice", "data1", "read"});

    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data1", "write");
    TestEnforceEx(e, evaluator, false, {});

    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data2", "read");
    TestEnforceEx(e, evaluator, false, {});

    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data2", "write");
    TestEnforceEx(e, evaluator, false, {});

    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data1", "read");
    TestEnforceEx(e, evaluator, false, {});

    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data1", "write");
    TestEnforceEx(e, evaluator, false, {});

    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data2", "read");
    TestEnforceEx(e, evaluator, false, {});

    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data2", "write");
    TestEnforceEx(e, evaluator, true, {"bob", "data2", "write"});

    // RBAC_MODEL
    e = casbin::Enforcer(rbac_model_path, rbac_policy_path);

    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data1", "read");
    TestEnforceEx(e, evaluator, true, {"alice", "data1", "read"});

    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data1", "write");
    TestEnforceEx(e, evaluator, false, {});

    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data2", "read");
    TestEnforceEx(e, evaluator, true, {"data2_admin", "data2", "read"});

    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data2", "write");
    TestEnforceEx(e, evaluator, true, {"data2_admin", "data2", "write"});

    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data1", "read");
    TestEnforceEx(e, evaluator, false, {});

    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data1", "write");
    TestEnforceEx(e, evaluator, false, {});

    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data2", "read");
    TestEnforceEx(e, evaluator, false, {});

    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data2", "write");
    TestEnforceEx(e, evaluator, true, {"bob", "data2", "write"});

    // PRIORITY_MODEL
    e = casbin::Enforcer(priority_model_path, priority_policy_path);

    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data1", "read");
    TestEnforceEx(e, evaluator, true, {"alice", "data1", "read", "allow"});

    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data1", "write");
    TestEnforceEx(e, evaluator, false, {"data1_deny_group", "data1", "write", "deny"});

    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data2", "read");
    TestEnforceEx(e, evaluator, false, {});

    evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data2", "write");
    TestEnforceEx(e, evaluator, false, {});

    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data1", "read");
    TestEnforceEx(e, evaluator, false, {});

    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data1", "write");
    TestEnforceEx(e, evaluator, false, {});

    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data2", "read");
    TestEnforceEx(e, evaluator, true, {"data2_allow_group", "data2", "read", "allow"});

    evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data2", "write");
    TestEnforceEx(e, evaluator, false, {"bob", "data2", "write", "deny"});
}

TEST(TestEnforcerEx, TestVectorParams) {
    // BASIC_MODEL_WITHOUT_SPACES
    casbin::Enforcer e(basic_model_without_spaces_path, basic_policy_path);

    TestEnforceEx(e, casbin::DataVector{"alice", "data1", "read"}, true, {"alice", "data1", "read"});
    TestEnforceEx(e, casbin::DataVector{"alice", "data1", "write"}, false, {});
    TestEnforceEx(e, casbin::DataVector{"alice", "data2", "read"}, false, {});
    TestEnforceEx(e, casbin::DataVector{"alice", "data2", "write"}, false, {});
    TestEnforceEx(e, casbin::DataVector{"bob", "data1", "read"}, false, {});
    TestEnforceEx(e, casbin::DataVector{"bob", "data1", "write"}, false, {});
    TestEnforceEx(e, casbin::DataVector{"bob", "data2", "read"}, false, {});
    TestEnforceEx(e, casbin::DataVector{"bob", "data2", "write"}, true, {"bob", "data2", "write"});

    // RBAC_MODEL
    e = casbin::Enforcer(rbac_model_path, rbac_policy_path);

    TestEnforceEx(e, casbin::DataVector{"alice", "data1", "read"}, true, {"alice", "data1", "read"});
    TestEnforceEx(e, casbin::DataVector{"alice", "data1", "write"}, false, {});
    TestEnforceEx(e, casbin::DataVector{"alice", "data2", "read"}, true, {"data2_admin", "data2", "read"});
    TestEnforceEx(e, casbin::DataVector{"alice", "data2", "write"}, true, {"data2_admin", "data2", "write"});
    TestEnforceEx(e, casbin::DataVector{"bob", "data1", "read"}, false, {});
    TestEnforceEx(e, casbin::DataVector{"bob", "data1", "write"}, false, {});
    TestEnforceEx(e, casbin::DataVector{"bob", "data2", "read"}, false, {});
    TestEnforceEx(e, casbin::DataVector{"bob", "data2", "write"}, true, {"bob", "data2", "write"});

    // PRIORITY_MODEL
    e = casbin::Enforcer(priority_model_path, priority_policy_path);

    TestEnforceEx(e, casbin::DataVector{"alice", "data1", "read"}, true, {"alice", "data1", "read", "allow"});
    TestEnforceEx(e, casbin::DataVector{"alice", "data1", "write"}, false, {"data1_deny_group", "data1", "write", "deny"});
    TestEnforceEx(e, casbin::DataVector{"alice", "data2", "read"}, false, {});
    TestEnforceEx(e, casbin::DataVector{"alice", "data2", "write"}, false, {});
    TestEnforceEx(e, casbin::DataVector{"bob", "data1", "read"}, false, {});
    TestEnforceEx(e, casbin::DataVector{"bob", "data1", "write"}, false, {});
    TestEnforceEx(e, casbin::DataVector{"bob", "data2", "read"}, true, {"data2_allow_group", "data2", "read", "allow"});
    TestEnforceEx(e, casbin::DataVector{"bob", "data2", "write"}, false, {"bob", "data2", "write", "deny"});
}

TEST(TestEnforcerEx, TestListParams) {
    // BASIC_MODEL_WITHOUT_SPACES
    casbin::Enforcer e(basic_model_without_spaces_path, basic_policy_path);

    TestEnforceEx(e, casbin::DataList{"alice", "data1", "read"}, true, {"alice", "data1", "read"});
    TestEnforceEx(e, casbin::DataList{"alice", "data1", "write"}, false, {});
    TestEnforceEx(e, casbin::DataList{"alice", "data2", "read"}, false, {});
    TestEnforceEx(e, casbin::DataList{"alice", "data2", "write"}, false, {});
    TestEnforceEx(e, casbin::DataList{"bob", "data1", "read"}, false, {});
    TestEnforceEx(e, casbin::DataList{"bob", "data1", "write"}, false, {});
    TestEnforceEx(e, casbin::DataList{"bob", "data2", "read"}, false, {});
    TestEnforceEx(e, casbin::DataList{"bob", "data2", "write"}, true, {"bob", "data2", "write"});

    // RBAC_MODEL
    e = casbin::Enforcer(rbac_model_path, rbac_policy_path);

    TestEnforceEx(e, casbin::DataList{"alice", "data1", "read"}, true, {"alice", "data1", "read"});
    TestEnforceEx(e, casbin::DataList{"alice", "data1", "write"}, false, {});
    TestEnforceEx(e, casbin::DataList{"alice", "data2", "read"}, true, {"data2_admin", "data2", "read"});
    TestEnforceEx(e, casbin::DataList{"alice", "data2", "write"}, true, {"data2_admin", "data2", "write"});
    TestEnforceEx(e, casbin::DataList{"bob", "data1", "read"}, false, {});
    TestEnforceEx(e, casbin::DataList{"bob", "data1", "write"}, false, {});
    TestEnforceEx(e, casbin::DataList{"bob", "data2", "read"}, false, {});
    TestEnforceEx(e, casbin::DataList{"bob", "data2", "write"}, true, {"bob", "data2", "write"});

    // PRIORITY_MODEL
    e = casbin::Enforcer(priority_model_path, priority_policy_path);

    TestEnforceEx(e, casbin::DataList{"alice", "data1", "read"}, true, {"alice", "data1", "read", "allow"});
    TestEnforceEx(e, casbin::DataList{"alice", "data1", "write"}, false, {"data1_deny_group", "data1", "write", "deny"});
    TestEnforceEx(e, casbin::DataList{"alice", "data2", "read"}, false, {});
    TestEnforceEx(e, casbin::DataList{"alice", "data2", "write"}, false, {});
    TestEnforceEx(e, casbin::DataList{"bob", "data1", "read"}, false, {});
    TestEnforceEx(e, casbin::DataList{"bob", "data1", "write"}, false, {});
    TestEnforceEx(e, casbin::DataList{"bob", "data2", "read"}, true, {"data2_allow_group", "data2", "read", "allow"});
    TestEnforceEx(e, casbin::DataList{"bob", "data2", "write"}, false, {"bob", "data2", "write", "deny"});
}

TEST(TestEnforcerEx, TestMapParams) {
    // BASIC_MODEL_WITHOUT_SPACES
    casbin::Enforcer e(basic_model_without_spaces_path, basic_policy_path);

    TestEnforceEx(e, casbin::DataMap{{"sub", "alice"}, {"obj", "data1"}, {"act", "read"}}, true, {"alice", "data1", "read"});
    TestEnforceEx(e, casbin::DataMap{{"sub", "alice"}, {"obj", "data1"}, {"act", "write"}}, false, {});
    TestEnforceEx(e, casbin::DataMap{{"sub", "alice"}, {"obj", "data2"}, {"act", "read"}}, false, {});
    TestEnforceEx(e, casbin::DataMap{{"sub", "alice"}, {"obj", "data2"}, {"act", "write"}}, false, {});
    TestEnforceEx(e, casbin::DataMap{{"sub", "bob"}, {"obj", "data1"}, {"act", "read"}}, false, {});
    TestEnforceEx(e, casbin::DataMap{{"sub", "bob"}, {"obj", "data1"}, {"act", "write"}}, false, {});
    TestEnforceEx(e, casbin::DataMap{{"sub", "bob"}, {"obj", "data2"}, {"act", "read"}}, false, {});
    TestEnforceEx(e, casbin::DataMap{{"sub", "bob"}, {"obj", "data2"}, {"act", "write"}}, true, {"bob", "data2", "write"});

    // RBAC_MODEL
    e = casbin::Enforcer(rbac_model_path, rbac_policy_path);

    TestEnforceEx(e, casbin::DataMap{{"sub", "alice"}, {"obj", "data1"}, {"act", "read"}}, true, {"alice", "data1", "read"});
    TestEnforceEx(e, casbin::DataMap{{"sub", "alice"}, {"obj", "data1"}, {"act", "write"}}, false, {});
    TestEnforceEx(e, casbin::DataMap{{"sub", "alice"}, {"obj", "data2"}, {"act", "read"}}, true, {"data2_admin", "data2", "read"});
    TestEnforceEx(e, casbin::DataMap{{"sub", "alice"}, {"obj", "data2"}, {"act", "write"}}, true, {"data2_admin", "data2", "write"});
    TestEnforceEx(e, casbin::DataMap{{"sub", "bob"}, {"obj", "data1"}, {"act", "read"}}, false, {});
    TestEnforceEx(e, casbin::DataMap{{"sub", "bob"}, {"obj", "data1"}, {"act", "write"}}, false, {});
    TestEnforceEx(e, casbin::DataMap{{"sub", "bob"}, {"obj", "data2"}, {"act", "read"}}, false, {});
    TestEnforceEx(e, casbin::DataMap{{"sub", "bob"}, {"obj", "data2"}, {"act", "write"}}, true, {"bob", "data2", "write"});

    // PRIORITY_MODEL
    e = casbin::Enforcer(priority_model_path, priority_policy_path);

    TestEnforceEx(e, casbin::DataMap{{"sub", "alice"}, {"obj", "data1"}, {"act", "read"}}, true, {"alice", "data1", "read", "allow"});
    TestEnforceEx(e, casbin::DataMap{{"sub", "alice"}, {"obj", "data1"}, {"act", "write"}}, false, {"data1_deny_group", "data1", "write", "deny"});
    TestEnforceEx(e, casbin::DataMap{{"sub", "alice"}, {"obj", "data2"}, {"act", "read"}}, false, {});
    TestEnforceEx(e, casbin::DataMap{{"sub", "alice"}, {"obj", "data2"}, {"act", "write"}}, false, {});
    TestEnforceEx(e, casbin::DataMap{{"sub", "bob"}, {"obj", "data1"}, {"act", "write"}}, false, {});
    TestEnforceEx(e, casbin::DataMap{{"sub", "bob"}, {"obj", "data2"}, {"act", "read"}}, true, {"data2_allow_group", "data2", "read", "allow"});
    TestEnforceEx(e, casbin::DataMap{{"sub", "bob"}, {"obj", "data2"}, {"act", "write"}}, false, {"bob", "data2", "write", "deny"});
}

// TEST(TestEnforcer, JsonData) {
//     using json = nlohmann::json;
//     casbin::Scope scope = casbin::InitializeScope();
//     casbin::PushObject(scope, "r");

//     json myJson = {
//             {"DoubleCase", 3.141},
//             {"IntegerCase", 2},
//             {"BoolenCase", true},
//             {"StringCase", "Bob"},
//             // {"nothing", nullptr},
//             {"x", {
//                     {"y", {
//                         {"z", 1}
//                         }
//                     },
//                     {"x", 2
//                     }
//                 }
//             },
//         };

//     casbin::PushObjectPropFromJson(scope, myJson, "r");
//     std::string s1 = "r.DoubleCase == 3.141;";
//     std::string s2 = "r.IntegerCase == 2;";
//     std::string s3 = "r.BoolenCase == true;";
//     std::string s4 = "r.StringCase == \"Bob\";";
//     std::string s5 = "r.x.y.z == 1;";
//     std::string s6 = "r.x.x == 2;";

//     auto EvalAndGetTop = [] (casbin::Scope scope, std::string s) -> bool  {
//        casbin::Eval(scope, s);
//        return casbin::GetBoolean(scope, -1);
//     };

//     ASSERT_TRUE(EvalAndGetTop(scope, s1));
//     ASSERT_TRUE(EvalAndGetTop(scope, s2));
//     ASSERT_TRUE(EvalAndGetTop(scope, s3));
//     ASSERT_TRUE(EvalAndGetTop(scope, s4));
//     ASSERT_TRUE(EvalAndGetTop(scope, s5));
//     ASSERT_TRUE(EvalAndGetTop(scope, s6));

//     s1 = "r.DoubleCase == 3.14;";
//     s2 = "r.IntegerCase == 1;";
//     s3 = "r.BoolenCase == false;";
//     s4 = "r.StringCase == \"BoB\";";
//     s5 = "r.x.y.z == 2;";
//     s6 = "r.x.x == 1;";

//     ASSERT_TRUE(!EvalAndGetTop(scope, s1));
//     ASSERT_TRUE(!EvalAndGetTop(scope, s2));
//     ASSERT_TRUE(!EvalAndGetTop(scope, s3));
//     ASSERT_TRUE(!EvalAndGetTop(scope, s4));
//     ASSERT_TRUE(!EvalAndGetTop(scope, s5));
//     ASSERT_TRUE(!EvalAndGetTop(scope, s6));
// }

} // namespace
