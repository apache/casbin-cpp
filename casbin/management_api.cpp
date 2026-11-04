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

#include "casbin/pch.h"

#ifndef MANAGEMENT_API_CPP
#define MANAGEMENT_API_CPP

#include "casbin/enforcer.h"

namespace casbin {

// GetAllSubjects gets the list of subjects that show up in the current policy.
std::vector<std::string> Enforcer ::GetAllSubjects() {
    return m_model->GetValuesForFieldInPolicyAllTypes("p", 0);
}

// GetAllNamedSubjects gets the list of subjects that show up in the current named policy.
std::vector<std::string> Enforcer ::GetAllNamedSubjects(const std::string& p_type) {
    return m_model->GetValuesForFieldInPolicy("p", p_type, 0);
}

// GetAllObjects gets the list of objects that show up in the current policy.
std::vector<std::string> Enforcer ::GetAllObjects() {
    return m_model->GetValuesForFieldInPolicyAllTypes("p", 1);
}

// GetAllNamedObjects gets the list of objects that show up in the current named policy.
std::vector<std::string> Enforcer ::GetAllNamedObjects(const std::string& p_type) {
    return m_model->GetValuesForFieldInPolicy("p", p_type, 1);
}

// GetAllActions gets the list of actions that show up in the current policy.
std::vector<std::string> Enforcer ::GetAllActions() {
    return m_model->GetValuesForFieldInPolicyAllTypes("p", 2);
}

// GetAllNamedActions gets the list of actions that show up in the current named policy.
std::vector<std::string> Enforcer ::GetAllNamedActions(const std::string& p_type) {
    return m_model->GetValuesForFieldInPolicy("p", p_type, 2);
}

// GetAllRoles gets the list of roles that show up in the current policy.
std::vector<std::string> Enforcer ::GetAllRoles() {
    return m_model->GetValuesForFieldInPolicyAllTypes("g", 1);
}

// GetAllNamedRoles gets the list of roles that show up in the current named policy.
std::vector<std::string> Enforcer ::GetAllNamedRoles(const std::string& p_type) {
    return m_model->GetValuesForFieldInPolicy("g", p_type, 1);
}

// GetPolicy gets all the authorization rules in the policy.
PoliciesValues Enforcer ::GetPolicy() {
    return this->GetNamedPolicy("p");
}

// GetFilteredPolicy gets all the authorization rules in the policy, field filters can be specified.
PoliciesValues Enforcer ::GetFilteredPolicy(int field_index, const std::vector<std::string>& field_values) {
    return this->GetFilteredNamedPolicy("p", field_index, field_values);
}

// GetNamedPolicy gets all the authorization rules in the named policy.
PoliciesValues Enforcer ::GetNamedPolicy(const std::string& p_type) {
    return m_model->GetPolicy("p", p_type);
}

// GetFilteredNamedPolicy gets all the authorization rules in the named policy, field filters can be specified.
PoliciesValues Enforcer ::GetFilteredNamedPolicy(const std::string& p_type, int field_index, const std::vector<std::string>& field_values) {
    return m_model->GetFilteredPolicy("p", p_type, field_index, field_values);
}

// GetGroupingPolicy gets all the role inheritance rules in the policy.
PoliciesValues Enforcer ::GetGroupingPolicy() {
    return this->GetNamedGroupingPolicy("g");
}

// GetFilteredGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
PoliciesValues Enforcer ::GetFilteredGroupingPolicy(int field_index, const std::vector<std::string>& field_values) {
    return this->GetFilteredNamedGroupingPolicy("g", field_index, field_values);
}

// GetNamedGroupingPolicy gets all the role inheritance rules in the policy.
PoliciesValues Enforcer ::GetNamedGroupingPolicy(const std::string& p_type) {
    return m_model->GetPolicy("g", p_type);
}

// GetFilteredNamedGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
PoliciesValues Enforcer ::GetFilteredNamedGroupingPolicy(const std::string& p_type, int field_index, const std::vector<std::string>& field_values) {
    return m_model->GetFilteredPolicy("g", p_type, field_index, field_values);
}

// HasPolicy determines whether an authorization rule exists.
bool Enforcer ::HasPolicy(const std::vector<std::string>& params) {
    return this->HasNamedPolicy("p", params);
}

// HasNamedPolicy determines whether a named authorization rule exists.
bool Enforcer ::HasNamedPolicy(const std::string& p_type, const std::vector<std::string>& params) {
    if (params.size() == 1) {
        std::vector<std::string> str_slice{params[0]};
        return m_model->HasPolicy("p", p_type, str_slice);
    }

    std::vector<std::string> policy;
    for (int i = 0; i < params.size(); i++)
        policy.push_back(params[i]);
    return m_model->HasPolicy("p", p_type, policy);
}

// AddPolicy adds an authorization rule to the current policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
bool Enforcer ::AddPolicy(const std::vector<std::string>& params) {
    return this->AddNamedPolicy("p", params);
}

// AddPolicies adds authorization rules to the current policy.
// If the rule already exists, the function returns false for the corresponding rule and the rule will not be added.
// Otherwise the function returns true for the corresponding rule by adding the new rule.
bool Enforcer ::AddPolicies(const PoliciesValues& rules) {
    return this->AddNamedPolicies("p", rules);
}

// AddNamedPolicy adds an authorization rule to the current named policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
bool Enforcer ::AddNamedPolicy(const std::string& p_type, const std::vector<std::string>& params) {
    if (params.size() == 1) {
        std::vector<std::string> str_slice{params[0]};
        return this->addPolicy("p", p_type, str_slice);
    }

    return this->addPolicy("p", p_type, params);
}

// AddNamedPolicies adds authorization rules to the current named policy.
// If the rule already exists, the function returns false for the corresponding rule and the rule will not be added.
// Otherwise the function returns true for the corresponding by adding the new rule.
bool Enforcer ::AddNamedPolicies(const std::string& p_type, const PoliciesValues& rules) {
    return this->addPolicies("p", p_type, rules);
}

// RemovePolicy removes an authorization rule from the current policy.
bool Enforcer ::RemovePolicy(const std::vector<std::string>& params) {
    return this->RemoveNamedPolicy("p", params);
}

// RemovePolicies removes authorization rules from the current policy.
bool Enforcer ::RemovePolicies(const PoliciesValues& rules) {
    return this->RemoveNamedPolicies("p", rules);
}

// RemoveFilteredPolicy removes an authorization rule from the current policy, field filters can be specified.
bool Enforcer ::RemoveFilteredPolicy(int field_index, const std::vector<std::string>& field_values) {
    return this->RemoveFilteredNamedPolicy("p", field_index, field_values);
}

// RemoveNamedPolicy removes an authorization rule from the current named policy.
bool Enforcer ::RemoveNamedPolicy(const std::string& p_type, const std::vector<std::string>& params) {
    if (params.size() == 1) {
        std::vector<std::string> str_slice{params[0]};
        return this->removePolicy("p", p_type, str_slice);
    }

    std::vector<std::string> policy;
    for (int i = 0; i < params.size(); i++)
        policy.push_back(params[i]);
    return this->removePolicy("p", p_type, policy);
}

// RemoveNamedPolicies removes authorization rules from the current named policy.
bool Enforcer ::RemoveNamedPolicies(const std::string& p_type, const PoliciesValues& rules) {
    return this->removePolicies("p", p_type, rules);
}

// RemoveFilteredNamedPolicy removes an authorization rule from the current named policy, field filters can be specified.
bool Enforcer ::RemoveFilteredNamedPolicy(const std::string& p_type, int field_index, const std::vector<std::string>& field_values) {
    return this->removeFilteredPolicy("p", p_type, field_index, field_values);
}

// HasGroupingPolicy determines whether a role inheritance rule exists.
bool Enforcer ::HasGroupingPolicy(const std::vector<std::string>& params) {
    return this->HasNamedGroupingPolicy("g", params);
}

// HasNamedGroupingPolicy determines whether a named role inheritance rule exists.
bool Enforcer ::HasNamedGroupingPolicy(const std::string& p_type, const std::vector<std::string>& params) {
    if (params.size() == 1) {
        std::vector<std::string> str_slice{params[0]};
        return m_model->HasPolicy("g", p_type, str_slice);
    }

    std::vector<std::string> policy;
    for (int i = 0; i < params.size(); i++)
        policy.push_back(params[i]);
    return m_model->HasPolicy("g", p_type, policy);
}

// AddGroupingPolicy adds a role inheritance rule to the current policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
bool Enforcer ::AddGroupingPolicy(const std::vector<std::string>& params) {
    return this->AddNamedGroupingPolicy("g", params);
}

// AddGroupingPolicies adds role inheritance rulea to the current policy.
// If the rule already exists, the function returns false for the corresponding policy rule and the rule will not be added.
// Otherwise the function returns true for the corresponding policy rule by adding the new rule.
bool Enforcer ::AddGroupingPolicies(const PoliciesValues& rules) {
    return this->AddNamedGroupingPolicies("g", rules);
}

// AddNamedGroupingPolicy adds a named role inheritance rule to the current policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
bool Enforcer ::AddNamedGroupingPolicy(const std::string& p_type, const std::vector<std::string>& params) {
    bool rule_added;
    if (params.size() == 1) {
        std::vector<std::string> str_slice{params[0]};
        rule_added = this->addPolicy("g", p_type, str_slice);
    } else {
        std::vector<std::string> policy;
        for (int i = 0; i < params.size(); i++)
            policy.push_back(params[i]);

        rule_added = this->addPolicy("g", p_type, policy);
    }

    if (m_auto_build_role_links)
        this->BuildIncrementalRoleLinks(policy_add, p_type, PoliciesValues({params}));
    // this->BuildRoleLinks();

    return rule_added;
}

// AddNamedGroupingPolicies adds named role inheritance rules to the current policy.
// If the rule already exists, the function returns false for the corresponding policy rule and the rule will not be added.
// Otherwise the function returns true for the corresponding policy rule by adding the new rule.
bool Enforcer ::AddNamedGroupingPolicies(const std::string& p_type, const PoliciesValues& rules) {
    return this->addPolicies("g", p_type, rules);
}

// RemoveGroupingPolicy removes a role inheritance rule from the current policy.
bool Enforcer ::RemoveGroupingPolicy(const std::vector<std::string>& params) {
    return this->RemoveNamedGroupingPolicy("g", params);
}

// RemoveGroupingPolicies removes role inheritance rulea from the current policy.
bool Enforcer ::RemoveGroupingPolicies(const PoliciesValues& rules) {
    return this->RemoveNamedGroupingPolicies("g", rules);
}

// RemoveFilteredGroupingPolicy removes a role inheritance rule from the current policy, field filters can be specified.
bool Enforcer ::RemoveFilteredGroupingPolicy(int field_index, const std::vector<std::string>& field_values) {
    return this->RemoveFilteredNamedGroupingPolicy("g", field_index, field_values);
}

// RemoveNamedGroupingPolicy removes a role inheritance rule from the current named policy.
bool Enforcer ::RemoveNamedGroupingPolicy(const std::string& p_type, const std::vector<std::string>& params) {
    bool rule_removed;
    if (params.size() == 1) {
        std::vector<std::string> str_slice{params[0]};
        rule_removed = this->removePolicy("g", p_type, str_slice);
    } else {
        std::vector<std::string> policy;
        for (int i = 0; i < params.size(); i++)
            policy.push_back(params[i]);

        rule_removed = this->removePolicy("g", p_type, policy);
    }

    if (m_auto_build_role_links)
        this->BuildRoleLinks();

    return rule_removed;
}

// RemoveNamedGroupingPolicies removes role inheritance rules from the current named policy.
bool Enforcer ::RemoveNamedGroupingPolicies(const std::string& p_type, const PoliciesValues& rules) {
    return this->removePolicies("g", p_type, rules);
}

// RemoveFilteredNamedGroupingPolicy removes a role inheritance rule from the current named policy, field filters can be specified.
bool Enforcer ::RemoveFilteredNamedGroupingPolicy(const std::string& p_type, int field_index, const std::vector<std::string>& field_values) {
    bool rule_removed = this->removeFilteredPolicy("g", p_type, field_index, field_values);

    if (m_auto_build_role_links)
        this->BuildRoleLinks();

    return rule_removed;
}

bool Enforcer ::UpdateGroupingPolicy(const std::vector<std::string>& oldRule, const std::vector<std::string>& newRule) {
    return UpdateNamedGroupingPolicy("g", oldRule, newRule);
}

bool Enforcer ::UpdateNamedGroupingPolicy(const std::string& p_type, const std::vector<std::string>& oldRule, const std::vector<std::string>& newRule) {
    return this->updatePolicy("g", p_type, oldRule, newRule);
}

// UpdatePolicy updates an authorization rule from the current policy.
bool Enforcer ::UpdatePolicy(const std::vector<std::string>& oldPolicy, const std::vector<std::string>& newPolicy) {
    return UpdateNamedPolicy("p", oldPolicy, newPolicy);
}

bool Enforcer ::UpdateNamedPolicy(const std::string& ptype, const std::vector<std::string>& p1, const std::vector<std::string>& p2) {
    return this->updatePolicy("p", ptype, p1, p2);
}

// UpdatePolicies updates authorization rules from the current policies.
bool Enforcer ::UpdatePolicies(const PoliciesValues& oldPolices, const PoliciesValues& newPolicies) {
    return UpdateNamedPolicies("p", oldPolices, newPolicies);
}

bool Enforcer ::UpdateNamedPolicies(const std::string& ptype, const PoliciesValues& p1, const PoliciesValues& p2) {
    return this->updatePolicies("p", ptype, p1, p2);
}

// AddNamedMatchingFunc add MatchingFunc by ptype RoleManager
bool Enforcer ::AddNamedMatchingFunc(const std::string& ptype, const std::string& name, casbin::MatchingFunc func) {
    auto default_rm = dynamic_cast<casbin::DefaultRoleManager*>(this->rm.get());
    default_rm->AddMatchingFunc(func);

    return true;
}

} // namespace casbin

#endif // MANAGEMENT_API_CPP
