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

#ifndef CASBIN_CPP_ENFORCER_INTERFACE
#define CASBIN_CPP_ENFORCER_INTERFACE

#include "casbin/data_types.h"
#include "casbin/effect/effector.h"
#include "casbin/model/evaluator.h"
#include "casbin/model/model.h"
#include "casbin/persist/adapter.h"
#include "casbin/persist/default_watcher.h"
#include "casbin/rbac/default_role_manager.h"

namespace casbin {

// IEnforcer is the API interface of Enforcer
class IEnforcer {
public:
    /* Enforcer API */
    virtual void InitWithFile(const std::string& model_path, const std::string& policy_path) = 0;
    virtual void InitWithAdapter(const std::string& model_path, std::shared_ptr<Adapter> adapter) = 0;
    virtual void InitWithModelAndAdapter(const std::shared_ptr<Model>& m, std::shared_ptr<Adapter> adapter) = 0;
    virtual void Initialize() = 0;
    virtual void LoadModel() = 0;
    virtual std::shared_ptr<Model> GetModel() = 0;
    virtual void SetModel(const std::shared_ptr<Model>& m) = 0;
    virtual std::shared_ptr<Adapter> GetAdapter() = 0;
    virtual void SetAdapter(std::shared_ptr<Adapter> adapter) = 0;
    virtual void SetWatcher(std::shared_ptr<Watcher> watcher) = 0;
    virtual std::shared_ptr<RoleManager> GetRoleManager() = 0;
    virtual void SetRoleManager(std::shared_ptr<RoleManager>& rm) = 0;
    virtual void SetEffector(std::shared_ptr<Effector> eft) = 0;
    virtual void ClearPolicy() = 0;
    virtual void LoadPolicy() = 0;

    template <typename Filter>
    void LoadFilteredPolicy(Filter filter);

    virtual bool IsFiltered() = 0;
    virtual void SavePolicy() = 0;
    virtual void EnableEnforce(bool enable) = 0;
    // virtual void EnableLog(bool enable) = 0;
    virtual void EnableAutoNotifyWatcher(bool enable) = 0;
    virtual void EnableAutoSave(bool auto_save) = 0;
    virtual void EnableAutoBuildRoleLinks(bool auto_build_role_links) = 0;
    virtual void BuildRoleLinks() = 0;
    virtual bool m_enforce(const std::string& matcher, std::vector<std::string>& explains, std::shared_ptr<IEvaluator> evalator) = 0;
    virtual bool Enforce(std::shared_ptr<IEvaluator> evalator) = 0;
    virtual bool EnforceWithMatcher(const std::string& matcher, std::shared_ptr<IEvaluator> evalator) = 0;
    virtual bool EnforceEx(std::shared_ptr<IEvaluator> evalator, std::vector<std::string>& explain) = 0;
    virtual bool EnforceExWithMatcher(const std::string& matcher, std::shared_ptr<IEvaluator> evalator, std::vector<std::string>& explain) = 0;
    virtual std::vector<bool> BatchEnforce(const std::initializer_list<DataList>& requests) = 0;
    virtual std::vector<bool> BatchEnforceWithMatcher(const std::string& matcher, const std::initializer_list<DataList>& requests) = 0;

    /* RBAC API */
    virtual std::vector<std::string> GetRolesForUser(const std::string& name, const std::vector<std::string>& domain = {}) = 0;
    virtual std::vector<std::string> GetUsersForRole(const std::string& name, const std::vector<std::string>& domain = {}) = 0;
    virtual bool HasRoleForUser(const std::string& name, const std::string& role) = 0;
    virtual bool AddRoleForUser(const std::string& user, const std::string& role) = 0;
    virtual bool AddRolesForUser(const std::string& user, const std::vector<std::string>& roles) = 0;
    virtual bool AddPermissionForUser(const std::string& user, const std::vector<std::string>& permission) = 0;
    virtual bool DeletePermissionForUser(const std::string& user, const std::vector<std::string>& permission) = 0;
    virtual bool DeletePermissionsForUser(const std::string& user) = 0;
    virtual PoliciesValues GetPermissionsForUser(const std::string& user) = 0;
    virtual bool HasPermissionForUser(const std::string& user, const std::vector<std::string>& permission) = 0;
    virtual std::vector<std::string> GetImplicitRolesForUser(const std::string& name, const std::vector<std::string>& domain = {}) = 0;
    virtual PoliciesValues GetImplicitPermissionsForUser(const std::string& user, const std::vector<std::string>& domain = {}) = 0;
    virtual std::vector<std::string> GetImplicitUsersForPermission(const std::vector<std::string>& permission) = 0;
    virtual bool DeleteRoleForUser(const std::string& user, const std::string& role) = 0;
    virtual bool DeleteRolesForUser(const std::string& user) = 0;
    virtual bool DeleteUser(const std::string& user) = 0;
    virtual bool DeleteRole(const std::string& role) = 0;
    virtual bool DeletePermission(const std::vector<std::string>& permission) = 0;

    /* Management API */
    virtual std::vector<std::string> GetAllSubjects() = 0;
    virtual std::vector<std::string> GetAllNamedSubjects(const std::string& p_type) = 0;
    virtual std::vector<std::string> GetAllObjects() = 0;
    virtual std::vector<std::string> GetAllNamedObjects(const std::string& p_type) = 0;
    virtual std::vector<std::string> GetAllActions() = 0;
    virtual std::vector<std::string> GetAllNamedActions(const std::string& p_type) = 0;
    virtual std::vector<std::string> GetAllRoles() = 0;
    virtual std::vector<std::string> GetAllNamedRoles(const std::string& p_type) = 0;
    virtual PoliciesValues GetPolicy() = 0;
    virtual PoliciesValues GetFilteredPolicy(int field_index, const std::vector<std::string>& field_values) = 0;
    virtual PoliciesValues GetNamedPolicy(const std::string& p_type) = 0;
    virtual PoliciesValues GetFilteredNamedPolicy(const std::string& p_type, int field_index, const std::vector<std::string>& field_values) = 0;
    virtual PoliciesValues GetGroupingPolicy() = 0;
    virtual PoliciesValues GetFilteredGroupingPolicy(int field_index, const std::vector<std::string>& field_values) = 0;
    virtual PoliciesValues GetNamedGroupingPolicy(const std::string& p_type) = 0;
    virtual PoliciesValues GetFilteredNamedGroupingPolicy(const std::string& p_type, int field_index, const std::vector<std::string>& field_values) = 0;
    virtual bool HasPolicy(const std::vector<std::string>& params) = 0;
    virtual bool HasNamedPolicy(const std::string& p_type, const std::vector<std::string>& params) = 0;
    virtual bool AddPolicy(const std::vector<std::string>& params) = 0;
    virtual bool AddPolicies(const PoliciesValues& rules) = 0;
    virtual bool AddNamedPolicy(const std::string& p_type, const std::vector<std::string>& params) = 0;
    virtual bool AddNamedPolicies(const std::string& p_type, const PoliciesValues& rules) = 0;
    virtual bool RemovePolicy(const std::vector<std::string>& params) = 0;
    virtual bool RemovePolicies(const PoliciesValues& rules) = 0;
    virtual bool RemoveFilteredPolicy(int field_index, const std::vector<std::string>& field_values) = 0;
    virtual bool RemoveNamedPolicy(const std::string& p_type, const std::vector<std::string>& params) = 0;
    virtual bool RemoveNamedPolicies(const std::string& p_type, const PoliciesValues& rules) = 0;
    virtual bool RemoveFilteredNamedPolicy(const std::string& p_type, int field_index, const std::vector<std::string>& field_values) = 0;
    virtual bool HasGroupingPolicy(const std::vector<std::string>& params) = 0;
    virtual bool HasNamedGroupingPolicy(const std::string& p_type, const std::vector<std::string>& params) = 0;
    virtual bool AddGroupingPolicy(const std::vector<std::string>& params) = 0;
    virtual bool AddGroupingPolicies(const PoliciesValues& rules) = 0;
    virtual bool AddNamedGroupingPolicy(const std::string& p_type, const std::vector<std::string>& params) = 0;
    virtual bool AddNamedGroupingPolicies(const std::string& p_type, const PoliciesValues& rules) = 0;
    virtual bool RemoveGroupingPolicy(const std::vector<std::string>& params) = 0;
    virtual bool RemoveGroupingPolicies(const PoliciesValues& rules) = 0;
    virtual bool RemoveFilteredGroupingPolicy(int field_index, const std::vector<std::string>& field_values) = 0;
    virtual bool RemoveNamedGroupingPolicy(const std::string& p_type, const std::vector<std::string>& params) = 0;
    virtual bool RemoveNamedGroupingPolicies(const std::string& p_type, const PoliciesValues& rules) = 0;
    virtual bool RemoveFilteredNamedGroupingPolicy(const std::string& p_type, int field_index, const std::vector<std::string>& field_values) = 0;
    virtual bool UpdateGroupingPolicy(const std::vector<std::string>& oldRule, const std::vector<std::string>& newRule) = 0;
    virtual bool UpdateNamedGroupingPolicy(const std::string& ptype, const std::vector<std::string>& oldRule, const std::vector<std::string>& newRule) = 0;
    virtual bool UpdatePolicy(const std::vector<std::string>& oldPolicy, const std::vector<std::string>& newPolicy) = 0;
    virtual bool UpdateNamedPolicy(const std::string& ptype, const std::vector<std::string>& p1, const std::vector<std::string>& p2) = 0;
    virtual bool UpdatePolicies(const PoliciesValues& oldPolices, const PoliciesValues& newPolicies) = 0;
    virtual bool UpdateNamedPolicies(const std::string& ptype, const PoliciesValues& p1, const PoliciesValues& p2) = 0;
    virtual bool AddNamedMatchingFunc(const std::string& ptype, const std::string& name, casbin::MatchingFunc func) = 0;

    /* Internal API member functions */
    virtual bool addPolicy(const std::string& sec, const std::string& p_type, const std::vector<std::string>& rule) = 0;
    virtual bool addPolicies(const std::string& sec, const std::string& p_type, const PoliciesValues& rules) = 0;
    virtual bool removePolicy(const std::string& sec, const std::string& p_type, const std::vector<std::string>& rule) = 0;
    virtual bool removePolicies(const std::string& sec, const std::string& p_type, const PoliciesValues& rules) = 0;
    virtual bool removeFilteredPolicy(const std::string& sec, const std::string& p_type, int field_index, const std::vector<std::string>& field_values) = 0;
    virtual bool updatePolicy(const std::string& sec, const std::string& p_type, const std::vector<std::string>& oldRule, const std::vector<std::string>& newRule) = 0;
    virtual bool updatePolicies(const std::string& sec, const std::string& p_type, const PoliciesValues& p1, const PoliciesValues& p2) = 0;

    /* RBAC API with domains.*/
    virtual std::vector<std::string> GetUsersForRoleInDomain(const std::string& name, const std::string& domain) = 0;
    virtual std::vector<std::string> GetRolesForUserInDomain(const std::string& name, const std::string& domain) = 0;
    virtual PoliciesValues GetPermissionsForUserInDomain(const std::string& user, const std::string& domain) = 0;
    virtual bool AddRoleForUserInDomain(const std::string& user, const std::string& role, const std::string& domain) = 0;
    virtual bool DeleteRoleForUserInDomain(const std::string& user, const std::string& role, const std::string& domain) = 0;
};

} // namespace casbin

#endif
