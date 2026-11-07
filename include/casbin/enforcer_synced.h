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

#ifndef CASBIN_H_ENFORCER_SYNC
#define CASBIN_H_ENFORCER_SYNC

#include <atomic>
#include <memory>
#include <mutex>
#include <shared_mutex>

#include "./enforcer.h"
#include "./persist/watcher.h"
#include "./util/ticker.h"

namespace casbin {

class SyncedEnforcer : public Enforcer {
    std::shared_mutex policyMutex;
    std::atomic_bool autoLoadRunning;
    std::atomic_int n;
    std::shared_ptr<Watcher> watcher;
    std::unique_ptr<Ticker> ticker;

public:
    /**
     * Enforcer is the default constructor.
     */
    SyncedEnforcer();

    /**
     * Enforcer initializes an enforcer with a model file and a policy file.
     *
     * @param model_path the path of the model file.
     * @param policy_file the path of the policy file.
     */
    SyncedEnforcer(const std::string& model_path, const std::string& policy_file);

    /**
     * Enforcer initializes an enforcer with a database adapter.
     *
     * @param model_path the path of the model file.
     * @param adapter the adapter.
     */
    SyncedEnforcer(const std::string& model_path, std::shared_ptr<Adapter> adapter);

    /**
     * Enforcer initializes an enforcer with a model and a database adapter.
     *
     * @param m the model.
     * @param adapter the adapter.
     */
    SyncedEnforcer(const std::shared_ptr<Model>& m, std::shared_ptr<Adapter> adapter);

    /**
     * Enforcer initializes an enforcer with a model.
     *
     * @param m the model.
     */
    SyncedEnforcer(const std::shared_ptr<Model>& m);

    /**
     * Enforcer initializes an enforcer with a model file.
     *
     * @param model_path the path of the model file.
     */
    SyncedEnforcer(const std::string& model_path);

    /**
     * Enforcer initializes an enforcer with a model file, a policy file and an enable log flag.
     *
     * @param model_path the path of the model file.
     * @param policy_file the path of the policy file.
     * @param enable_log whether to enable Casbin's log.
     */
    SyncedEnforcer(const std::string& model_path, const std::string& policy_file, bool enable_log);

    // StartAutoLoadPolicy starts a thread that will go through every specified duration call LoadPolicy
    void StartAutoLoadPolicy(std::chrono::duration<int64_t, std::nano> t);

    // IsAutoLoadingRunning check if SyncedEnforcer is auto loading policies
    bool IsAutoLoadingRunning();

    // StopAutoLoadPolicy causes the thread to exit
    void StopAutoLoadPolicy();

    std::string UpdateWrapper();

    // SetWatcher sets the current watcher.
    void SetWatcher(std::shared_ptr<Watcher> w) override;

    // LoadModel reloads the model from the model CONF file.
    void LoadModel() override;

    // ClearPolicy clears all policy.
    void ClearPolicy() override;

    // LoadPolicy reloads the policy from file/database.
    void LoadPolicy() override;

    void LoadPolicyWrapper();

    // LoadFilteredPolicy reloads a filtered policy from file/database.
    template <typename Filter>
    void LoadFilteredPolicy(Filter);

    // LoadIncrementalFilteredPolicy reloads a filtered policy from file/database.
    void LoadIncrementalFilteredPolicy(Filter);

    // SavePolicy saves the current policy (usually after changed with Casbin API) back to file/database.
    void SavePolicy() override;

    // BuildRoleLinks manually rebuild the role inheritance relations.
    void BuildRoleLinks() override;

    // Enforce decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
    bool Enforce(std::shared_ptr<IEvaluator>) override;

    // Enforce with a vector param,decides whether a "subject" can access a
    // "object" with the operation "action", input parameters are usually: (sub,
    // obj, act).
    bool Enforce(const DataVector& params) override;

    // Enforce with a vector param,decides whether a "subject" can access a
    // "object" with the operation "action", input parameters are usually: (sub,
    // obj, act).
    bool Enforce(const DataList& params) override;

    // Enforce with a map param,decides whether a "subject" can access a "object"
    // with the operation "action", input parameters are usually: (sub, obj, act).
    bool Enforce(const DataMap& params) override;

    // BatchEnforce enforce in batches
    std::vector<bool> BatchEnforce(const std::initializer_list<DataList>& requests) override;

    // BatchEnforceWithMatcher enforce with matcher in batches
    std::vector<bool> BatchEnforceWithMatcher(const std::string& matcher, const std::initializer_list<DataList>& requests) override;

    // GetAllSubjects gets the list of subjects that show up in the current policy.
    std::vector<std::string> GetAllSubjects() override;

    // GetAllNamedSubjects gets the list of subjects that show up in the current named policy.
    std::vector<std::string> GetAllNamedSubjects(const std::string& ptype) override;

    // GetAllObjects gets the list of objects that show up in the current policy.
    std::vector<std::string> GetAllObjects() override;

    // GetAllNamedObjects gets the list of objects that show up in the current named policy.
    std::vector<std::string> GetAllNamedObjects(const std::string& ptype) override;

    // GetAllNamedActions gets the list of actions that show up in the current named policy.
    std::vector<std::string> GetAllNamedActions(const std::string& ptype) override;

    // GetAllRoles gets the list of roles that show up in the current policy.
    std::vector<std::string> GetAllRoles() override;

    // GetAllNamedRoles gets the list of roles that show up in the current named policy.
    std::vector<std::string> GetAllNamedRoles(const std::string& ptype) override;

    // GetPolicy gets all the authorization rules in the policy.
    PoliciesValues GetPolicy() override;

    // GetNamedPolicy gets all the authorization rules in the named policy.
    PoliciesValues GetNamedPolicy(const std::string& ptype) override;

    // GetFilteredNamedPolicy gets all the authorization rules in the named policy, field filters can be specified.
    PoliciesValues GetFilteredNamedPolicy(const std::string& ptype, int fieldIndex, const std::vector<std::string>& fieldValues) override;

    // GetGroupingPolicy gets all the role inheritance rules in the policy.
    PoliciesValues GetGroupingPolicy() override;

    // GetFilteredGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
    PoliciesValues GetFilteredGroupingPolicy(int fieldIndex, const std::vector<std::string>& fieldValues) override;

    // GetNamedGroupingPolicy gets all the role inheritance rules in the policy.
    PoliciesValues GetNamedGroupingPolicy(const std::string& ptype) override;

    // GetFilteredNamedGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
    PoliciesValues GetFilteredNamedGroupingPolicy(const std::string& ptype, int fieldIndex, const std::vector<std::string>& fieldValues) override;

    // HasPolicy determines whether an authorization rule exists.
    bool HasPolicy(const std::vector<std::string>& params) override;

    // HasNamedPolicy determines whether a named authorization rule exists.
    bool HasNamedPolicy(const std::string& ptype, const std::vector<std::string>& params) override;

    // AddPolicy adds an authorization rule to the current policy.
    // If the rule already exists, the function returns false and the rule will not be added.
    // Otherwise the function returns true by adding the new rule.
    bool AddPolicy(const std::vector<std::string>& params) override;

    // AddPolicies adds authorization rules to the current policy.
    // If the rule already exists, the function returns false for the corresponding rule and the rule will not be added.
    // Otherwise the function returns true for the corresponding rule by adding the new rule.
    bool AddPolicies(const PoliciesValues& rules) override;

    // AddNamedPolicy adds an authorization rule to the current named policy.
    // If the rule already exists, the function returns false and the rule will not be added.
    // Otherwise the function returns true by adding the new rule.
    bool AddNamedPolicy(const std::string& ptype, const std::vector<std::string>& params) override;

    // AddNamedPolicies adds authorization rules to the current named policy.
    // If the rule already exists, the function returns false for the corresponding rule and the rule will not be added.
    // Otherwise the function returns true for the corresponding by adding the new rule.
    bool AddNamedPolicies(const std::string& ptype, const PoliciesValues& rules) override;

    // RemovePolicy removes an authorization rule from the current policy.
    bool RemovePolicy(const std::vector<std::string>& params) override;

    // UpdatePolicy updates an authorization rule from the current policy.
    bool UpdatePolicy(const std::vector<std::string>& oldPolicy, const std::vector<std::string>& newPolicy) override;

    bool UpdateNamedPolicy(const std::string& ptype, const std::vector<std::string>& p1, const std::vector<std::string>& p2) override;

    // UpdatePolicies updates authorization rules from the current policies.
    bool UpdatePolicies(const PoliciesValues& oldPolices, const PoliciesValues& newPolicies) override;

    bool UpdateNamedPolicies(const std::string& ptype, const PoliciesValues& p1, const PoliciesValues& p2) override;

    // RemovePolicies removes authorization rules from the current policy.
    bool RemovePolicies(const PoliciesValues& rules) override;

    // RemoveFilteredPolicy removes an authorization rule from the current policy, field filters can be specified.
    bool RemoveFilteredPolicy(int fieldIndex, const std::vector<std::string>& fieldValues) override;

    // RemoveNamedPolicy removes an authorization rule from the current named policy.
    bool RemoveNamedPolicy(const std::string& ptype, const std::vector<std::string>& params) override;

    // RemoveNamedPolicies removes authorization rules from the current named policy.
    bool RemoveNamedPolicies(const std::string& ptype, const PoliciesValues& rules) override;

    // RemoveFilteredNamedPolicy removes an authorization rule from the current named policy, field filters can be specified.
    bool RemoveFilteredNamedPolicy(const std::string& ptype, int fieldIndex, const std::vector<std::string>& fieldValues) override;

    // HasGroupingPolicy determines whether a role inheritance rule exists.
    bool HasGroupingPolicy(const std::vector<std::string>& params) override;

    // HasNamedGroupingPolicy determines whether a named role inheritance rule exists.
    bool HasNamedGroupingPolicy(const std::string& ptype, const std::vector<std::string>& params) override;

    // AddGroupingPolicy adds a role inheritance rule to the current policy.
    // If the rule already exists, the function returns false and the rule will not be added.
    // Otherwise the function returns true by adding the new rule.
    bool AddGroupingPolicy(const std::vector<std::string>& params) override;

    // AddGroupingPolicies adds role inheritance rulea to the current policy.
    // If the rule already exists, the function returns false for the corresponding policy rule and the rule will not be added.
    // Otherwise the function returns true for the corresponding policy rule by adding the new rule.
    bool AddGroupingPolicies(const PoliciesValues& rules) override;

    // AddNamedGroupingPolicy adds a named role inheritance rule to the current policy.
    // If the rule already exists, the function returns false and the rule will not be added.
    // Otherwise the function returns true by adding the new rule.
    bool AddNamedGroupingPolicy(const std::string& ptype, const std::vector<std::string>& params) override;

    // AddNamedGroupingPolicies adds named role inheritance rules to the current policy.
    // If the rule already exists, the function returns false for the corresponding policy rule and the rule will not be added.
    // Otherwise the function returns true for the corresponding policy rule by adding the new rule.
    bool AddNamedGroupingPolicies(const std::string& ptype, const PoliciesValues& rules) override;

    // RemoveGroupingPolicy removes a role inheritance rule from the current policy.
    bool RemoveGroupingPolicy(const std::vector<std::string>& params) override;

    // RemoveGroupingPolicies removes role inheritance rules from the current policy.
    bool RemoveGroupingPolicies(const PoliciesValues& rules) override;

    // RemoveFilteredGroupingPolicy removes a role inheritance rule from the current policy, field filters can be specified.
    bool RemoveFilteredGroupingPolicy(int fieldIndex, const std::vector<std::string>& fieldValues) override;

    // RemoveNamedGroupingPolicy removes a role inheritance rule from the current named policy.
    bool RemoveNamedGroupingPolicy(const std::string& ptype, const std::vector<std::string>& params) override;

    // RemoveNamedGroupingPolicies removes role inheritance rules from the current named policy.
    bool RemoveNamedGroupingPolicies(const std::string& ptype, const PoliciesValues& rules) override;

    bool UpdateGroupingPolicy(const std::vector<std::string>& oldRule, const std::vector<std::string>& newRule) override;

    bool UpdateNamedGroupingPolicy(const std::string& ptype, const std::vector<std::string>& oldRule, const std::vector<std::string>& newRule) override;

    // RemoveFilteredNamedGroupingPolicy removes a role inheritance rule from the current named policy, field filters can be specified.
    bool RemoveFilteredNamedGroupingPolicy(const std::string& ptype, int fieldIndex, const std::vector<std::string>& fieldValues) override;

    // GetAllActions gets the list of actions that show up in the current policy.

    std::vector<std::string> GetAllActions() override;

    // GetFilteredPolicy gets all the authorization rules in the policy, field filters can be specified.
    PoliciesValues GetFilteredPolicy(int fieldIndex, std::vector<std::string> fieldValues);

    // EnforceExWithMatcher use a custom matcher and explain enforcement by informing matched rules.
    bool SyncedEnforceExWithMatcher(const std::string& matcher, std::shared_ptr<IEvaluator> evalator, std::vector<std::string>& explain);

    bool SyncedEnforceExWithMatcher(const std::string& matcher, const DataList& params, std::vector<std::string>& explain);

    bool SyncedEnforceExWithMatcher(const std::string& matcher, const DataVector& params, std::vector<std::string>& explain);

    bool SyncedEnforceExWithMatcher(const std::string& matcher, const DataMap& params, std::vector<std::string>& explain);

    // EnforceEx explain enforcement by informing matched rules.
    bool SyncedEnforceEx(std::shared_ptr<IEvaluator> evalator, std::vector<std::string>& explain);

    bool SyncedEnforceEx(const DataList& params, std::vector<std::string>& explain);

    bool SyncedEnforceEx(const DataVector& params, std::vector<std::string>& explain);

    bool SyncedEnforceEx(const DataMap& params, std::vector<std::string>& explain);

    // EnforceWithMatcher use a custom matcher to decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (matcher, sub, obj, act), use model
    bool SyncedEnforceWithMatcher(const std::string& matcher, std::shared_ptr<IEvaluator> evalator);

    bool SyncedEnforceWithMatcher(const std::string& matcher, const DataList& params);

    bool SyncedEnforceWithMatcher(const std::string& matcher, const DataVector& params);

    bool SyncedEnforceWithMatcher(const std::string& matcher, const DataMap& params);
};

} // namespace casbin

#endif