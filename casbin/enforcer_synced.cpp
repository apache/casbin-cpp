/*
 * Copyright 2020 The casbin Authors. All Rights Reserved.
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
 */

#include "casbin/pch.h"

#ifndef ENFORCER_SYNCED_CPP
#define ENFORCER_SYNCED_CPP

#include <atomic>
#include <memory>
#include <mutex>

#include "casbin/enforcer_synced.h"
#include "casbin/persist/watcher.h"
#include "casbin/util/ticker.h"

namespace casbin {

/**
 * Enforcer is the default constructor.
 */
SyncedEnforcer ::SyncedEnforcer()
    : autoLoadRunning(false) {}

/**
 * Enforcer initializes an enforcer with a model file and a policy file.
 *
 * @param model_path the path of the model file.
 * @param policyFile the path of the policy file.
 */
SyncedEnforcer ::SyncedEnforcer(const std::string& model_path, const std::string& policy_file)
    : Enforcer(model_path, policy_file), autoLoadRunning(false) {}

/**
 * Enforcer initializes an enforcer with a database adapter.
 *
 * @param model_path the path of the model file.
 * @param adapter the adapter.
 */
SyncedEnforcer ::SyncedEnforcer(const std::string& model_path, std::shared_ptr<Adapter> adapter)
    : Enforcer(model_path, adapter), autoLoadRunning(false) {}

/**
 * Enforcer initializes an enforcer with a model and a database adapter.
 *
 * @param m the model.
 * @param adapter the adapter.
 */
SyncedEnforcer ::SyncedEnforcer(const std::shared_ptr<Model>& m, std::shared_ptr<Adapter> adapter)
    : Enforcer(m, adapter), autoLoadRunning(false) {}

/**
 * Enforcer initializes an enforcer with a model.
 *
 * @param m the model.
 */
SyncedEnforcer ::SyncedEnforcer(const std::shared_ptr<Model>& m)
    : Enforcer(m), autoLoadRunning(false) {}

/**
 * Enforcer initializes an enforcer with a model file.
 *
 * @param model_path the path of the model file.
 */
SyncedEnforcer ::SyncedEnforcer(const std::string& model_path)
    : Enforcer(model_path), autoLoadRunning(false) {}

/**
 * Enforcer initializes an enforcer with a model file, a policy file and an enable log flag.
 *
 * @param model_path the path of the model file.
 * @param policyFile the path of the policy file.
 * @param enableLog whether to enable Casbin's log.
 */
SyncedEnforcer ::SyncedEnforcer(const std::string& model_path, const std::string& policy_file, bool enable_log)
    : Enforcer(model_path, policy_file, enable_log), autoLoadRunning(false) {}

// SyncedEnforcer::SyncedEnforcer(const SyncedEnforcer& ce)
//    : Enforcer(ce), autoLoadRunning(ce.autoLoadRunning)
// {}

// SyncedEnforcer::SyncedEnforcer(SyncedEnforcer&& ce)
//   : Enforcer(ce), autoLoadRunning(ce->autoLoadRunning)
// {}

void SyncedEnforcer ::LoadPolicyWrapper() {
    Enforcer::LoadPolicy();
    ++n;
}

// StartAutoLoadPolicy starts a thread that will go through every specified duration call LoadPolicy
void SyncedEnforcer ::StartAutoLoadPolicy(std::chrono::duration<int64_t, std::nano> t) {
    if (IsAutoLoadingRunning())
        return;
    autoLoadRunning = true;
    Ticker::on_tick_t onTick = [this]() {
        SyncedEnforcer::LoadPolicy();
        ++n;
    };
    ticker = std::make_unique<Ticker>(onTick, t);
    n = 1;
    ticker->start();
}

// IsAutoLoadingRunning check if SyncedEnforcer is auto loading policies
bool SyncedEnforcer ::IsAutoLoadingRunning() {
    return autoLoadRunning;
}

// StopAutoLoadPolicy causes the thread to exit
void SyncedEnforcer ::StopAutoLoadPolicy() {
    if (ticker)
        ticker->stop();
    autoLoadRunning = false;
}

std::string SyncedEnforcer ::UpdateWrapper() {
    LoadPolicy();
    return "";
}

// SetWatcher sets the current watcher.
void SyncedEnforcer ::SetWatcher(std::shared_ptr<Watcher> w) {
    watcher = w;
    return watcher->SetUpdateCallback(&SyncedEnforcer::UpdateWrapper);
}

// LoadModel reloads the model from the model CONF file.
void SyncedEnforcer ::LoadModel() {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    Enforcer::LoadModel();
}

// ClearPolicy clears all policy.
void SyncedEnforcer ::ClearPolicy() {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    Enforcer::ClearPolicy();
}

// LoadPolicy reloads the policy from file/database.
void SyncedEnforcer ::LoadPolicy() {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    Enforcer::LoadPolicy();
}

// LoadFilteredPolicy reloads a filtered policy from file/database.
template <typename Filter>
void SyncedEnforcer ::LoadFilteredPolicy(Filter f) {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    Enforcer::LoadFilteredPolicy(f);
}

// LoadIncrementalFilteredPolicy reloads a filtered policy from file/database.
// void SyncedEnforcer ::LoadIncrementalFilteredPolicy(Filter f) {
//   std::lock_guard<std::mutex> lock(policyMutex);
//   Enforcer::LoadIncrementalFilteredPolicy(f);
// }

// SavePolicy saves the current policy (usually after changed with Casbin API) back to file/database.
void SyncedEnforcer ::SavePolicy() {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    Enforcer::SavePolicy();
}

// BuildRoleLinks manually rebuild the role inheritance relations.
void SyncedEnforcer ::BuildRoleLinks() {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    Enforcer::BuildRoleLinks();
}

// Enforce decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
bool SyncedEnforcer ::Enforce(std::shared_ptr<IEvaluator> evalator) {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::Enforce(evalator);
}

// Enforce with a vector param,decides whether a "subject" can access a
// "object" with the operation "action", input parameters are usually: (sub,
// obj, act).
bool SyncedEnforcer::Enforce(const DataVector& params) {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::Enforce(params);
}

// Enforce with a vector param,decides whether a "subject" can access a
// "object" with the operation "action", input parameters are usually: (sub,
// obj, act).
bool SyncedEnforcer ::Enforce(const DataList& params) {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::Enforce(params);
}

// Enforce with a map param,decides whether a "subject" can access a "object"
// with the operation "action", input parameters are usually: (sub, obj, act).
bool SyncedEnforcer ::Enforce(const DataMap& params) {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::Enforce(params);
}

// BatchEnforce enforce in batches
std::vector<bool> SyncedEnforcer ::BatchEnforce(const std::initializer_list<DataList>& requests) {
    std::unique_lock<std::shared_mutex> lock(policyMutex);

    // note: why not return Enforcer::BatchEnforce(requests) ?
    // Inside Enforcer::BatchEnforce, this->Enforce will be executed
    // but now 'this' is SyncedEnforcer, which means it will call SyncedEnforcer::Enforce
    // This will cause a deadlock

    std::vector<bool> results;
    results.reserve(requests.size());
    for (const auto& request : requests) {
        results.push_back(Enforcer::Enforce(request));
    }
    return results;
}

// BatchEnforceWithMatcher enforce with matcher in batches
std::vector<bool> SyncedEnforcer::BatchEnforceWithMatcher(const std::string& matcher, const std::initializer_list<DataList>& requests) {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    std::vector<bool> results;
    results.reserve(requests.size());
    for (const auto& request : requests) {
        results.push_back(Enforcer::EnforceWithMatcher(matcher, request));
    }
    return results;
}

// GetAllSubjects gets the list of subjects that show up in the current policy.
std::vector<std::string> SyncedEnforcer ::GetAllSubjects() {
    std::shared_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::GetAllSubjects();
}

// GetAllNamedSubjects gets the list of subjects that show up in the current named policy.
std::vector<std::string> SyncedEnforcer ::GetAllNamedSubjects(const std::string& ptype) {
    std::shared_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::GetAllNamedSubjects(ptype);
}

// GetAllObjects gets the list of objects that show up in the current policy.
std::vector<std::string> SyncedEnforcer ::GetAllObjects() {
    std::shared_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::GetAllObjects();
}

// GetAllNamedObjects gets the list of objects that show up in the current named policy.
std::vector<std::string> SyncedEnforcer ::GetAllNamedObjects(const std::string& ptype) {
    std::shared_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::GetAllNamedObjects(ptype);
}

// GetAllNamedActions gets the list of actions that show up in the current named policy.
std::vector<std::string> SyncedEnforcer ::GetAllNamedActions(const std::string& ptype) {
    std::shared_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::GetAllNamedActions(ptype);
}

// GetAllRoles gets the list of roles that show up in the current policy.
std::vector<std::string> SyncedEnforcer ::GetAllRoles() {
    std::shared_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::GetAllRoles();
}

// GetAllNamedRoles gets the list of roles that show up in the current named policy.
std::vector<std::string> SyncedEnforcer ::GetAllNamedRoles(const std::string& ptype) {
    std::shared_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::GetAllNamedRoles(ptype);
}

// GetPolicy gets all the authorization rules in the policy.
PoliciesValues SyncedEnforcer ::GetPolicy() {
    std::shared_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::GetPolicy();
}

// GetNamedPolicy gets all the authorization rules in the name:x::d policy.
PoliciesValues SyncedEnforcer ::GetNamedPolicy(const std::string& ptype) {
    std::shared_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::GetNamedPolicy(ptype);
}

// GetFilteredNamedPolicy gets all the authorization rules in the named policy, field filters can be specified.
PoliciesValues SyncedEnforcer ::GetFilteredNamedPolicy(const std::string& ptype, int fieldIndex, const std::vector<std::string>& fieldValues) {
    std::shared_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::GetFilteredNamedPolicy(ptype, fieldIndex, fieldValues);
}

// GetGroupingPolicy gets all the role inheritance rules in the policy.
PoliciesValues SyncedEnforcer ::GetGroupingPolicy() {
    std::shared_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::GetGroupingPolicy();
}

// GetFilteredGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
PoliciesValues SyncedEnforcer ::GetFilteredGroupingPolicy(int fieldIndex, const std::vector<std::string>& fieldValues) {
    std::shared_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::GetFilteredGroupingPolicy(fieldIndex, fieldValues);
}

// GetNamedGroupingPolicy gets all the role inheritance rules in the policy.
PoliciesValues SyncedEnforcer ::GetNamedGroupingPolicy(const std::string& ptype) {
    std::shared_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::GetNamedGroupingPolicy(ptype);
}

// GetFilteredNamedGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
PoliciesValues SyncedEnforcer ::GetFilteredNamedGroupingPolicy(const std::string& ptype, int fieldIndex, const std::vector<std::string>& fieldValues) {
    std::shared_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::GetFilteredNamedGroupingPolicy(ptype, fieldIndex, fieldValues);
}

// HasPolicy determines whether an authorization rule exists.
bool SyncedEnforcer ::HasPolicy(const std::vector<std::string>& params) {
    std::shared_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::HasPolicy(params);
}

// HasNamedPolicy determines whether a named authorization rule exists.
bool SyncedEnforcer ::HasNamedPolicy(const std::string& ptype, const std::vector<std::string>& params) {
    std::shared_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::HasNamedPolicy(ptype, params);
}

// AddPolicy adds an authorization rule to the current policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
bool SyncedEnforcer ::AddPolicy(const std::vector<std::string>& params) {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::AddPolicy(params);
}

// AddPolicies adds authorization rules to the current policy.
// If the rule already exists, the function returns false for the corresponding rule and the rule will not be added.
// Otherwise the function returns true for the corresponding rule by adding the new rule.
bool SyncedEnforcer ::AddPolicies(const PoliciesValues& rules) {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::AddPolicies(rules);
}

// AddNamedPolicy adds an authorization rule to the current named policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
bool SyncedEnforcer ::AddNamedPolicy(const std::string& ptype, const std::vector<std::string>& params) {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::AddNamedPolicy(ptype, params);
}

// AddNamedPolicies adds authorization rules to the current named policy.
// If the rule already exists, the function returns false for the corresponding rule and the rule will not be added.
// Otherwise the function returns true for the corresponding by adding the new rule.
bool SyncedEnforcer ::AddNamedPolicies(const std::string& ptype, const PoliciesValues& rules) {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::AddNamedPolicies(ptype, rules);
}

// RemovePolicy removes an authorization rule from the current policy.
bool SyncedEnforcer ::RemovePolicy(const std::vector<std::string>& params) {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::RemovePolicy(params);
}

// UpdatePolicy updates an authorization rule from the current policy.
bool SyncedEnforcer ::UpdatePolicy(const std::vector<std::string>& oldPolicy, const std::vector<std::string>& newPolicy) {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::UpdatePolicy(oldPolicy, newPolicy);
}

bool SyncedEnforcer ::UpdateNamedPolicy(const std::string& ptype, const std::vector<std::string>& p1, const std::vector<std::string>& p2) {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::UpdateNamedPolicy(ptype, p1, p2);
}

// UpdatePolicies updates authorization rules from the current policies.
bool SyncedEnforcer ::UpdatePolicies(const PoliciesValues& oldPolices, const PoliciesValues& newPolicies) {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::UpdatePolicies(oldPolices, newPolicies);
}

bool SyncedEnforcer ::UpdateNamedPolicies(const std::string& ptype, const PoliciesValues& p1, const PoliciesValues& p2) {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::UpdateNamedPolicies(ptype, p1, p2);
}

// RemovePolicies removes authorization rules from the current policy.
bool SyncedEnforcer ::RemovePolicies(const PoliciesValues& rules) {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::RemovePolicies(rules);
}

// RemoveFilteredPolicy removes an authorization rule from the current policy, field filters can be specified.
bool SyncedEnforcer ::RemoveFilteredPolicy(int fieldIndex, const std::vector<std::string>& fieldValues) {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::RemoveFilteredPolicy(fieldIndex, fieldValues);
}

// RemoveNamedPolicy removes an authorization rule from the current named policy.
bool SyncedEnforcer ::RemoveNamedPolicy(const std::string& ptype, const std::vector<std::string>& params) {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::RemoveNamedPolicy(ptype, params);
}

// RemoveNamedPolicies removes authorization rules from the current named policy.
bool SyncedEnforcer ::RemoveNamedPolicies(const std::string& ptype, const PoliciesValues& rules) {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::RemoveNamedPolicies(ptype, rules);
}

// RemoveFilteredNamedPolicy removes an authorization rule from the current named policy, field filters can be specified.
bool SyncedEnforcer ::RemoveFilteredNamedPolicy(const std::string& ptype, int fieldIndex, const std::vector<std::string>& fieldValues) {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::RemoveFilteredNamedPolicy(ptype, fieldIndex, fieldValues);
}

// HasGroupingPolicy determines whether a role inheritance rule exists.
bool SyncedEnforcer ::HasGroupingPolicy(const std::vector<std::string>& params) {
    std::shared_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::HasGroupingPolicy(params);
}

// HasNamedGroupingPolicy determines whether a named role inheritance rule exists.
bool SyncedEnforcer ::HasNamedGroupingPolicy(const std::string& ptype, const std::vector<std::string>& params) {
    std::shared_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::HasNamedGroupingPolicy(ptype, params);
}

// AddGroupingPolicy adds a role inheritance rule to the current policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
bool SyncedEnforcer ::AddGroupingPolicy(const std::vector<std::string>& params) {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::AddGroupingPolicy(params);
}

// AddGroupingPolicies adds role inheritance rulea to the current policy.
// If the rule already exists, the function returns false for the corresponding policy rule and the rule will not be added.
// Otherwise the function returns true for the corresponding policy rule by adding the new rule.
bool SyncedEnforcer ::AddGroupingPolicies(const PoliciesValues& rules) {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::AddGroupingPolicies(rules);
}

// AddNamedGroupingPolicy adds a named role inheritance rule to the current policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
bool SyncedEnforcer ::AddNamedGroupingPolicy(const std::string& ptype, const std::vector<std::string>& params) {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::AddNamedGroupingPolicy(ptype, params);
}

// AddNamedGroupingPolicies adds named role inheritance rules to the current policy.
// If the rule already exists, the function returns false for the corresponding policy rule and the rule will not be added.
// Otherwise the function returns true for the corresponding policy rule by adding the new rule.
bool SyncedEnforcer ::AddNamedGroupingPolicies(const std::string& ptype, const PoliciesValues& rules) {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::AddNamedGroupingPolicies(ptype, rules);
}

// RemoveGroupingPolicy removes a role inheritance rule from the current policy.
bool SyncedEnforcer ::RemoveGroupingPolicy(const std::vector<std::string>& params) {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::RemoveGroupingPolicy(params);
}

// RemoveGroupingPolicies removes role inheritance rules from the current policy.
bool SyncedEnforcer ::RemoveGroupingPolicies(const PoliciesValues& rules) {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::RemoveGroupingPolicies(rules);
}

// RemoveFilteredGroupingPolicy removes a role inheritance rule from the current policy, field filters can be specified.
bool SyncedEnforcer ::RemoveFilteredGroupingPolicy(int fieldIndex, const std::vector<std::string>& fieldValues) {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::RemoveFilteredGroupingPolicy(fieldIndex, fieldValues);
}

// RemoveNamedGroupingPolicy removes a role inheritance rule from the current named policy.
bool SyncedEnforcer ::RemoveNamedGroupingPolicy(const std::string& ptype, const std::vector<std::string>& params) {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::RemoveNamedGroupingPolicy(ptype, params);
}

// RemoveNamedGroupingPolicies removes role inheritance rules from the current named policy.
bool SyncedEnforcer ::RemoveNamedGroupingPolicies(const std::string& ptype, const PoliciesValues& rules) {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::RemoveNamedGroupingPolicies(ptype, rules);
}

bool SyncedEnforcer ::UpdateGroupingPolicy(const std::vector<std::string>& oldRule, const std::vector<std::string>& newRule) {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::UpdateGroupingPolicy(oldRule, newRule);
}

bool SyncedEnforcer ::UpdateNamedGroupingPolicy(const std::string& ptype, const std::vector<std::string>& oldRule, const std::vector<std::string>& newRule) {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::UpdateNamedGroupingPolicy(ptype, oldRule, newRule);
}

// RemoveFilteredNamedGroupingPolicy removes a role inheritance rule from the current named policy, field filters can be specified.
bool SyncedEnforcer ::RemoveFilteredNamedGroupingPolicy(const std::string& ptype, int fieldIndex, const std::vector<std::string>& fieldValues) {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::RemoveFilteredNamedGroupingPolicy(ptype, fieldIndex, fieldValues);
}

// GetAllActions gets the list of actions that show up in the current policy.
std::vector<std::string> SyncedEnforcer::GetAllActions() {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::GetAllActions();
}

// GetFilteredPolicy gets all the authorization rules in the policy, field filters can be specified.
PoliciesValues SyncedEnforcer::GetFilteredPolicy(int fieldIndex, std::vector<std::string> fieldValues) {
   std::unique_lock<std::shared_mutex> lock(policyMutex);
   return Enforcer::GetFilteredPolicy(fieldIndex, fieldValues);
}

// EnforceExWithMatcher use a custom matcher and explain enforcement by informing matched rules.
bool SyncedEnforcer::SyncedEnforceExWithMatcher(const std::string& matcher, std::shared_ptr<IEvaluator> evalator, std::vector<std::string>& explain) {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::EnforceExWithMatcher(matcher, evalator, explain);
}

bool SyncedEnforcer::SyncedEnforceExWithMatcher(const std::string& matcher, const DataList& params, std::vector<std::string>& explain) {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::EnforceExWithMatcher(matcher, params, explain);
}

bool SyncedEnforcer::SyncedEnforceExWithMatcher(const std::string& matcher, const DataVector& params, std::vector<std::string>& explain) {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::EnforceExWithMatcher(matcher, params, explain);
}

bool SyncedEnforcer::SyncedEnforceExWithMatcher(const std::string& matcher, const DataMap& params, std::vector<std::string>& explain) {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::EnforceExWithMatcher(matcher, params, explain);
}

// EnforceEx explain enforcement by informing matched rules.
bool SyncedEnforcer::SyncedEnforceEx(std::shared_ptr<IEvaluator> evalator, std::vector<std::string>& explain) {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::EnforceEx(evalator, explain);
}

bool SyncedEnforcer::SyncedEnforceEx(const DataList& params, std::vector<std::string>& explain) {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::EnforceEx(params, explain);
}

bool SyncedEnforcer::SyncedEnforceEx(const DataVector& params, std::vector<std::string>& explain) {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::EnforceEx(params, explain);
}

bool SyncedEnforcer::SyncedEnforceEx(const DataMap& params, std::vector<std::string>& explain) {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::EnforceEx(params, explain);
}

// EnforceWithMatcher use a custom matcher to decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (matcher, sub, obj, act), use model matcher by default when matcher is "".
bool SyncedEnforcer::SyncedEnforceWithMatcher(const std::string& matcher, std::shared_ptr<IEvaluator> evalator) {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::EnforceWithMatcher(matcher, evalator);
}

bool SyncedEnforcer::SyncedEnforceWithMatcher(const std::string& matcher, const DataList& params) {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::EnforceWithMatcher(matcher, params);
}

bool SyncedEnforcer::SyncedEnforceWithMatcher(const std::string& matcher, const DataVector& params) {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::EnforceWithMatcher(matcher, params);
}

bool SyncedEnforcer::SyncedEnforceWithMatcher(const std::string& matcher, const DataMap& params) {
    std::unique_lock<std::shared_mutex> lock(policyMutex);
    return Enforcer::EnforceWithMatcher(matcher, params);
}

} // namespace casbin

#endif // ENFORCER_SYNCED_CPP
