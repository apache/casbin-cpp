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

#ifndef CASBIN_CPP_ENFORCER
#define CASBIN_CPP_ENFORCER

#include <tuple>
#include <vector>

#include "casbin/enforcer_interface.h"
#include "casbin/log/log_util.h"
#include "casbin/model/evaluator.h"
#include "casbin/model/function.h"
#include "casbin/persist/filtered_adapter.h"
#include "casbin/rbac/role_manager.h"

namespace casbin {

// Enforcer is the main interface for authorization enforcement and policy management.
class Enforcer : public IEnforcer {
private:
    std::string m_model_path;
    std::shared_ptr<Model> m_model;
    std::shared_ptr<Effector> m_eft;

    std::shared_ptr<Adapter> m_adapter;
    std::shared_ptr<Watcher> m_watcher;
    std::shared_ptr<IEvaluator> m_evalator;
    LogUtil m_log;

    bool m_enabled;
    bool m_auto_save;
    bool m_auto_build_role_links;
    bool m_auto_notify_watcher;

    // enforce use a custom matcher to decides whether a "subject" can access a "object"
    // with the operation "action", input parameters are usually: (matcher, sub, obj, act),
    // use model matcher by default when matcher is "".
    bool m_enforce(const std::string& matcher, std::vector<std::string>& explains, std::shared_ptr<IEvaluator> evalator) override;

public:
    std::shared_ptr<RoleManager> rm;

    /**
     * Enforcer is the default constructor.
     */
    Enforcer();
    /**
     * Enforcer initializes an enforcer with a model file and a policy file.
     *
     * @param model_path the path of the model file.
     * @param policy_file the path of the policy file.
     */
    Enforcer(const std::string& model_path, const std::string& policy_file);
    /**
     * Enforcer initializes an enforcer with a database adapter.
     *
     * @param model_path the path of the model file.
     * @param adapter the adapter.
     */
    Enforcer(const std::string& model_path, std::shared_ptr<Adapter> adapter);
    /**
     * Enforcer initializes an enforcer with a model and a database adapter.
     *
     * @param m the model.
     * @param adapter the adapter.
     */
    Enforcer(const std::shared_ptr<Model>& m, std::shared_ptr<Adapter> adapter);
    /**
     * Enforcer initializes an enforcer with a model.
     *
     * @param m the model.
     */
    Enforcer(const std::shared_ptr<Model>& m);
    /**
     * Enforcer initializes an enforcer with a model file.
     *
     * @param model_path the path of the model file.
     */
    Enforcer(const std::string& model_path);
    /**
     * Enforcer initializes an enforcer with a model file, a policy file and an enable log flag.
     *
     * @param model_path the path of the model file.
     * @param policy_file the path of the policy file.
     * @param enable_log whether to enable Casbin's log.
     */
    Enforcer(const std::string& model_path, const std::string& policy_file, bool enable_log);
    // Destructor of Enforcer.
    ~Enforcer();
    // InitWithFile initializes an enforcer with a model file and a policy file.
    void InitWithFile(const std::string& model_path, const std::string& policy_path) override;
    // InitWithAdapter initializes an enforcer with a database adapter.
    void InitWithAdapter(const std::string& model_path, std::shared_ptr<Adapter> adapter) override;
    // InitWithModelAndAdapter initializes an enforcer with a model and a database adapter.
    void InitWithModelAndAdapter(const std::shared_ptr<Model>& m, std::shared_ptr<Adapter> adapter) override;
    void Initialize() override;
    // LoadModel reloads the model from the model CONF file.
    // Because the policy is attached to a model, so the policy is invalidated and
    // needs to be reloaded by calling LoadPolicy().
    void LoadModel() override;
    // GetModel gets the current model.
    std::shared_ptr<Model> GetModel() override;
    // SetModel sets the current model.
    void SetModel(const std::shared_ptr<Model>& m) override;
    // GetAdapter gets the current adapter.
    std::shared_ptr<Adapter> GetAdapter() override;
    // SetAdapter sets the current adapter.
    void SetAdapter(std::shared_ptr<Adapter> adapter) override;
    // SetWatcher sets the current watcher.
    void SetWatcher(std::shared_ptr<Watcher> watcher) override;
    // SetWatcher sets the current watcher.
    void SetEvaluator(std::shared_ptr<IEvaluator> evaluator);
    // GetRoleManager gets the current role manager.
    std::shared_ptr<RoleManager> GetRoleManager() override;
    // SetRoleManager sets the current role manager.
    void SetRoleManager(std::shared_ptr<RoleManager>& rm) override;
    // SetEffector sets the current effector.
    void SetEffector(std::shared_ptr<Effector> eft) override;
    // ClearPolicy clears all policy.
    void ClearPolicy() override;
    // LoadPolicy reloads the policy from file/database.
    void LoadPolicy() override;
    // LoadFilteredPolicy reloads a filtered policy from file/database.
    template <typename Filter>
    void LoadFilteredPolicy(Filter filter);
    // IsFiltered returns true if the loaded policy has been filtered.
    bool IsFiltered() override;
    // SavePolicy saves the current policy (usually after changed with Casbin API) back to file/database.
    void SavePolicy() override;
    // EnableEnforce changes the enforcing state of Casbin, when Casbin is disabled, all access will be allowed by the Enforce() function.
    void EnableEnforce(bool enable) override;
    // EnableLog changes whether Casbin will log messages to the Logger.
    void EnableLog(bool enable);

    // EnableAutoNotifyWatcher controls whether to save a policy rule automatically notify the Watcher when it is added or removed.
    void EnableAutoNotifyWatcher(bool enable) override;
    // EnableAutoSave controls whether to save a policy rule automatically to the adapter when it is added or removed.
    void EnableAutoSave(bool auto_save) override;
    // EnableAutoBuildRoleLinks controls whether to rebuild the role inheritance relations when a role is added or deleted.
    void EnableAutoBuildRoleLinks(bool auto_build_role_links) override;
    // BuildRoleLinks manually rebuild the role inheritance relations.
    void BuildRoleLinks() override;
    // BuildIncrementalRoleLinks provides incremental build the role inheritance relations.
    void BuildIncrementalRoleLinks(policy_op op, const std::string& p_type, const PoliciesValues& rules);
    // Enforce decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
    bool Enforce(std::shared_ptr<IEvaluator> evalator) override;
    // Enforce with a list param, decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
    virtual bool Enforce(const DataList& params);
    // Enforce with a vector param, decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
    virtual bool Enforce(const DataVector& params);
    // Enforce with a map param,decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
    virtual bool Enforce(const DataMap& params);
    // EnforceWithMatcher use a custom matcher to decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (matcher, sub, obj, act), use model
    // matcher by default when matcher is "".
    bool EnforceWithMatcher(const std::string& matcher, std::shared_ptr<IEvaluator> evalator) override;
    // EnforceWithMatcher use a custom matcher to decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (matcher, sub, obj, act), use model
    // matcher by default when matcher is "".
    bool EnforceWithMatcher(const std::string& matcher, const DataList& params);
    // EnforceWithMatcher use a custom matcher to decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (matcher, sub, obj, act), use model
    // matcher by default when matcher is "".
    bool EnforceWithMatcher(const std::string& matcher, const DataVector& params);
    // EnforceWithMatcher use a custom matcher to decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (matcher, sub, obj, act), use model
    // matcher by default when matcher is "".
    bool EnforceWithMatcher(const std::string& matcher, const DataMap& params);

    bool EnforceEx(std::shared_ptr<IEvaluator> evalator, std::vector<std::string>& explain) override;
    bool EnforceEx(const DataList& params, std::vector<std::string>& explain);
    bool EnforceEx(const DataVector& params, std::vector<std::string>& explain);
    bool EnforceEx(const DataMap& params, std::vector<std::string>& explain);

    bool EnforceExWithMatcher(const std::string& matcher, std::shared_ptr<IEvaluator> evalator, std::vector<std::string>& explain) override;
    bool EnforceExWithMatcher(const std::string& matcher, const DataList& params, std::vector<std::string>& explain);
    bool EnforceExWithMatcher(const std::string& matcher, const DataVector& params, std::vector<std::string>& explain);
    bool EnforceExWithMatcher(const std::string& matcher, const DataMap& params, std::vector<std::string>& explain);

    // BatchEnforce enforce in batches
    std::vector<bool> BatchEnforce(const std::initializer_list<DataList>& requests) override;
    // BatchEnforceWithMatcher enforce with matcher in batches
    std::vector<bool> BatchEnforceWithMatcher(const std::string& matcher, const std::initializer_list<DataList>& requests) override;

    /*Management API member functions.*/
    std::vector<std::string> GetAllSubjects() override;
    std::vector<std::string> GetAllNamedSubjects(const std::string& p_type) override;
    std::vector<std::string> GetAllObjects() override;
    std::vector<std::string> GetAllNamedObjects(const std::string& p_type) override;
    std::vector<std::string> GetAllActions() override;
    std::vector<std::string> GetAllNamedActions(const std::string& p_type) override;
    std::vector<std::string> GetAllRoles() override;
    std::vector<std::string> GetAllNamedRoles(const std::string& p_type) override;
    PoliciesValues GetPolicy() override;
    PoliciesValues GetFilteredPolicy(int field_index, const std::vector<std::string>& field_values) override;
    PoliciesValues GetNamedPolicy(const std::string& p_type) override;
    PoliciesValues GetFilteredNamedPolicy(const std::string& p_type, int field_index, const std::vector<std::string>& field_values) override;
    PoliciesValues GetGroupingPolicy() override;
    PoliciesValues GetFilteredGroupingPolicy(int field_index, const std::vector<std::string>& field_values) override;
    PoliciesValues GetNamedGroupingPolicy(const std::string& p_type) override;
    PoliciesValues GetFilteredNamedGroupingPolicy(const std::string& p_type, int field_index, const std::vector<std::string>& field_values) override;
    bool HasPolicy(const std::vector<std::string>& params) override;
    bool HasNamedPolicy(const std::string& p_type, const std::vector<std::string>& params) override;
    bool AddPolicy(const std::vector<std::string>& params) override;
    bool AddPolicies(const PoliciesValues& rules) override;
    bool AddNamedPolicy(const std::string& p_type, const std::vector<std::string>& params) override;
    bool AddNamedPolicies(const std::string& p_type, const PoliciesValues& rules) override;
    bool RemovePolicy(const std::vector<std::string>& params) override;
    bool RemovePolicies(const PoliciesValues& rules) override;
    bool RemoveFilteredPolicy(int field_index, const std::vector<std::string>& field_values) override;
    bool RemoveNamedPolicy(const std::string& p_type, const std::vector<std::string>& params) override;
    bool RemoveNamedPolicies(const std::string& p_type, const PoliciesValues& rules) override;
    bool RemoveFilteredNamedPolicy(const std::string& p_type, int field_index, const std::vector<std::string>& field_values) override;
    bool HasGroupingPolicy(const std::vector<std::string>& params) override;
    bool HasNamedGroupingPolicy(const std::string& p_type, const std::vector<std::string>& params) override;
    bool AddGroupingPolicy(const std::vector<std::string>& params) override;
    bool AddGroupingPolicies(const PoliciesValues& rules) override;
    bool AddNamedGroupingPolicy(const std::string& p_type, const std::vector<std::string>& params) override;
    bool AddNamedGroupingPolicies(const std::string& p_type, const PoliciesValues& rules) override;
    bool RemoveGroupingPolicy(const std::vector<std::string>& params) override;
    bool RemoveGroupingPolicies(const PoliciesValues& rules) override;
    bool RemoveFilteredGroupingPolicy(int field_index, const std::vector<std::string>& field_values) override;
    bool RemoveNamedGroupingPolicy(const std::string& p_type, const std::vector<std::string>& params) override;
    bool RemoveNamedGroupingPolicies(const std::string& p_type, const PoliciesValues& rules) override;
    bool RemoveFilteredNamedGroupingPolicy(const std::string& p_type, int field_index, const std::vector<std::string>& field_values) override;
    bool UpdateGroupingPolicy(const std::vector<std::string>& oldRule, const std::vector<std::string>& newRule) override;
    bool UpdateNamedGroupingPolicy(const std::string& ptype, const std::vector<std::string>& oldRule, const std::vector<std::string>& newRule) override;
    bool UpdatePolicy(const std::vector<std::string>& oldPolicy, const std::vector<std::string>& newPolicy) override;
    bool UpdateNamedPolicy(const std::string& ptype, const std::vector<std::string>& p1, const std::vector<std::string>& p2) override;
    bool UpdatePolicies(const PoliciesValues& oldPolices, const PoliciesValues& newPolicies) override;
    bool UpdateNamedPolicies(const std::string& ptype, const PoliciesValues& p1, const PoliciesValues& p2) override;
    bool AddNamedMatchingFunc(const std::string& ptype, const std::string& name, casbin::MatchingFunc func) override;

    /*RBAC API member functions.*/
    std::vector<std::string> GetRolesForUser(const std::string& name, const std::vector<std::string>& domain = {}) override;
    std::vector<std::string> GetUsersForRole(const std::string& name, const std::vector<std::string>& domain = {}) override;
    bool HasRoleForUser(const std::string& name, const std::string& role) override;
    bool AddRoleForUser(const std::string& user, const std::string& role) override;
    bool AddRolesForUser(const std::string& user, const std::vector<std::string>& roles) override;
    bool AddPermissionForUser(const std::string& user, const std::vector<std::string>& permission) override;
    bool DeletePermissionForUser(const std::string& user, const std::vector<std::string>& permission) override;
    bool DeletePermissionsForUser(const std::string& user) override;
    PoliciesValues GetPermissionsForUser(const std::string& user) override;
    bool HasPermissionForUser(const std::string& user, const std::vector<std::string>& permission) override;
    std::vector<std::string> GetImplicitRolesForUser(const std::string& name, const std::vector<std::string>& domain = {}) override;
    PoliciesValues GetImplicitPermissionsForUser(const std::string& user, const std::vector<std::string>& domain = {}) override;
    std::vector<std::string> GetImplicitUsersForPermission(const std::vector<std::string>& permission) override;
    bool DeleteRoleForUser(const std::string& user, const std::string& role) override;
    bool DeleteRolesForUser(const std::string& user) override;
    bool DeleteUser(const std::string& user) override;
    bool DeleteRole(const std::string& role) override;
    bool DeletePermission(const std::vector<std::string>& permission) override;

    /* Internal API member functions */
    bool addPolicy(const std::string& sec, const std::string& p_type, const std::vector<std::string>& rule) override;
    bool addPolicies(const std::string& sec, const std::string& p_type, const PoliciesValues& rules) override;
    bool removePolicy(const std::string& sec, const std::string& p_type, const std::vector<std::string>& rule) override;
    bool removePolicies(const std::string& sec, const std::string& p_type, const PoliciesValues& rules) override;
    bool removeFilteredPolicy(const std::string& sec, const std::string& p_type, int field_index, const std::vector<std::string>& field_values) override;
    bool updatePolicy(const std::string& sec, const std::string& p_type, const std::vector<std::string>& oldRule, const std::vector<std::string>& newRule) override;
    bool updatePolicies(const std::string& sec, const std::string& p_type, const PoliciesValues& p1, const PoliciesValues& p2) override;

    /* RBAC API with domains.*/
    std::vector<std::string> GetUsersForRoleInDomain(const std::string& name, const std::string& domain = {}) override;
    std::vector<std::string> GetRolesForUserInDomain(const std::string& name, const std::string& domain = {}) override;
    PoliciesValues GetPermissionsForUserInDomain(const std::string& user, const std::string& domain = {}) override;
    bool AddRoleForUserInDomain(const std::string& user, const std::string& role, const std::string& domain = {}) override;
    bool DeleteRoleForUserInDomain(const std::string& user, const std::string& role, const std::string& domain = {}) override;
};

} // namespace casbin

#endif
