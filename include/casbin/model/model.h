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

#ifndef CASBIN_CPP_MODEL_MODEL
#define CASBIN_CPP_MODEL_MODEL

#include <unordered_map>

#include "../config/config.h"
#include "../config/config_interface.h"
#include "./assertion.h"

namespace casbin {

// AssertionMap is the collection of assertions, can be "r", "p", "g", "e", "m".
class AssertionMap {
public:
    std::unordered_map<std::string, std::shared_ptr<Assertion>> assertion_map;
};

// Model represents the whole access control model.
class Model {
private:
    static std::unordered_map<std::string, std::string> section_name_map;

    static void LoadSection(Model* raw_ptr, std::shared_ptr<ConfigInterface> cfg, const std::string& sec);

    static std::string GetKeySuffix(int i);

    static bool LoadAssertion(Model* raw_ptr, std::shared_ptr<ConfigInterface> cfg, const std::string& sec, const std::string& key);

public:
    Model();

    Model(const std::string& path);

    std::unordered_map<std::string, AssertionMap> m;

    // Minimal required sections for a model to be valid
    static std::vector<std::string> required_sections;

    bool HasSection(const std::string& sec);

    // AddDef adds an assertion to the model.
    bool AddDef(const std::string& sec, const std::string& key, const std::string& value);

    // LoadModel loads the model from model CONF file.
    void LoadModel(const std::string& path);

    // LoadModelFromText loads the model from the text.
    void LoadModelFromText(const std::string& text);

    void LoadModelFromConfig(std::shared_ptr<Config>& cfg);

    // PrintModel prints the model to the log.
    void PrintModel();

    // NewModel creates an empty model.
    static std::shared_ptr<Model> NewModel();

    // NewModel creates a model from a .CONF file.
    static std::shared_ptr<Model> NewModelFromFile(const std::string& path);

    // NewModel creates a model from a std::string which contains model text.
    static std::shared_ptr<Model> NewModelFromString(const std::string& text);

    void BuildIncrementalRoleLinks(std::shared_ptr<RoleManager>& rm, policy_op op, const std::string& sec, const std::string& p_type, const PoliciesValues& rules);

    // BuildRoleLinks initializes the roles in RBAC.
    void BuildRoleLinks(std::shared_ptr<RoleManager>& rm);

    // PrintPolicy prints the policy to log.
    void PrintPolicy();

    // ClearPolicy clears all current policy.
    void ClearPolicy();

    // GetPolicy gets all rules in a policy.
    PoliciesValues GetPolicy(const std::string& sec, const std::string& p_type);

    // GetFilteredPolicy gets rules based on field filters from a policy.
    PoliciesValues GetFilteredPolicy(const std::string& sec, const std::string& p_type, int field_index, const std::vector<std::string>& field_values);

    // HasPolicy determines whether a model has the specified policy rule.
    bool HasPolicy(const std::string& sec, const std::string& p_type, const std::vector<std::string>& rule);

    // AddPolicy adds a policy rule to the model.
    bool AddPolicy(const std::string& sec, const std::string& p_type, const std::vector<std::string>& rule);

    // AddPolicies adds policy rules to the model.
    bool AddPolicies(const std::string& sec, const std::string& p_type, const PoliciesValues& rules);

    // UpdatePolicy updates a policy rule from the model.
    bool UpdatePolicy(const std::string& sec, const std::string& p_type, const std::vector<std::string>& oldRule, const std::vector<std::string>& newRule);

    // UpdatePolicies updates a set of policy rules from the model.
    bool UpdatePolicies(const std::string& sec, const std::string& p_type, const PoliciesValues& oldRules, const PoliciesValues& newRules);

    // RemovePolicy removes a policy rule from the model.
    bool RemovePolicy(const std::string& sec, const std::string& p_type, const std::vector<std::string>& rule);

    // RemovePolicies removes policy rules from the model.
    bool RemovePolicies(const std::string& sec, const std::string& p_type, const PoliciesValues& rules);

    // RemoveFilteredPolicy removes policy rules based on field filters from the model.
    std::pair<bool, PoliciesValues> RemoveFilteredPolicy(const std::string& sec, const std::string& p_type, int field_index, const std::vector<std::string>& field_values);

    // GetValuesForFieldInPolicy gets all values for a field for all rules in a policy, duplicated values are removed.
    std::vector<std::string> GetValuesForFieldInPolicy(const std::string& sec, const std::string& p_type, int field_index);

    // GetValuesForFieldInPolicyAllTypes gets all values for a field for all rules in a policy of all p_types, duplicated values are removed.
    std::vector<std::string> GetValuesForFieldInPolicyAllTypes(const std::string& sec, int field_index);
};

}; // namespace casbin

#endif