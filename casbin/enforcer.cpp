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

#ifndef ENFORCER_CPP
#define ENFORCER_CPP

#include <algorithm>
#include <regex>

#include "casbin/effect/default_effector.h"
#include "casbin/enforcer.h"
#include "casbin/selected_policies.h"
#include "casbin/exception/casbin_adapter_exception.h"
#include "casbin/exception/casbin_enforcer_exception.h"
#include "casbin/persist/file_adapter/batch_file_adapter.h"
#include "casbin/persist/file_adapter/file_adapter.h"
#include "casbin/persist/watcher_ex.h"
#include "casbin/model/policy_collection.hpp"
#include "casbin/rbac/default_role_manager.h"
#include "casbin/util/util.h"

namespace casbin {

// enforce use a custom matcher to decides whether a "subject" can access a "object"
// with the operation "action", input parameters are usually: (matcher, sub, obj, act),
// use model matcher by default when matcher is "".
bool Enforcer::m_enforce(const std::string& matcher, std::vector<std::string>& explains, std::shared_ptr<IEvaluator> evalator) {
    if (!explains.empty()) {
        explains.clear();
    }

    // when Casbin is disabled, all access will be allowed by the m_enforce()
    if (!m_enabled) {
        return true;
    }

    evalator->func_list.clear();
    evalator->LoadFunctions();

    // std::unordered_map<std::string, std::shared_ptr<RoleManager>> rm_map;
    if (m_model->m.find("g") != m_model->m.end()) {
        for (auto [assertion_name, assertion] : m_model->m["g"].assertion_map) {
            std::shared_ptr<RoleManager>& rm = assertion->rm;

            int char_count = static_cast<int>(std::count(assertion->value.begin(), assertion->value.end(), '_'));
            evalator->LoadGFunction(rm, assertion_name, char_count);
        }
    }

    std::string exp_string;
    if (matcher.empty()) {
        exp_string = m_model->m["m"].assertion_map["m"]->value;
    } else {
        exp_string = matcher;
    }

    std::unordered_map<std::string, int> r_int_tokens;
    const std::vector<std::string>& r_tokens = m_model->m["r"].assertion_map["r"]->tokens;
    r_int_tokens.reserve(r_tokens.size());

    for (int i = 0; i < r_tokens.size(); i++) {
        r_int_tokens[r_tokens[i]] = i;
    }

    std::unordered_map<std::string, int> p_int_tokens;
    const std::vector<std::string>& p_tokens = m_model->m["p"].assertion_map["p"]->tokens;
    p_int_tokens.reserve(p_tokens.size());

    for (int i = 0; i < p_tokens.size(); i++) {
        p_int_tokens[p_tokens[i]] = i;
    }

    bool hasEval = HasEval(exp_string);

    std::vector<Effect> policy_effects;
    std::vector<float> matcher_results;

    Effect effect;
    int explainIndex;

    SelectedPolicies selected_policies(evalator, matcher, m_model);
    PoliciesValues& p_policy = *selected_policies;

    if (auto policy_len = p_policy.size(); policy_len != 0) {
        policy_effects = std::vector<Effect>(policy_len, Effect::Indeterminate);
        matcher_results = std::vector<float>(policy_len, 0.0f);

        int policy_index = 0;
        for (auto& p_vals : p_policy ) {
            casbin::LogUtil::LogPrint("Policy Rule: ", p_vals);
            if (p_tokens.size() != p_vals.size()) {
                throw CasbinEnforcerException("invalid policy size");
                //  m_log.LogPrintf("invalid policy size: expected ", p_tokens.size(), ", got ",p_vals.size());
                //  return false;
            }

            evalator->Clean(m_model->m["p"], false);
            evalator->InitialObject("p");
            for (int j = 0; j < p_tokens.size(); j++) {
                size_t index = p_tokens[j].find('_');
                std::string token = p_tokens[j].substr(index + 1);
                evalator->PushObjectString("p", token, p_vals[j]);
            }

            if (hasEval) {
                auto ruleNames = GetEvalValue(exp_string);
                std::unordered_map<std::string, std::string> replacements;
                for (auto& ruleName : ruleNames) {
                    auto ruleNameCpy = EscapeAssertion(ruleName);

                    bool ok = p_int_tokens.find(ruleNameCpy) != p_int_tokens.end();
                    if (ok) {
                        int idx = p_int_tokens[ruleNameCpy];
                        replacements[ruleName] = p_vals[idx];
                    } else {
                        throw CasbinEnforcerException("please make sure rule exists in policy when using eval() in matcher");
                        // return false;
                    }
                }

                auto expWithRule = ReplaceEvalWithMap(exp_string, replacements);
                evalator->Eval(expWithRule);

            } else {
                evalator->Eval(exp_string);
            }

            // set to no-match at first
            matcher_results[policy_index] = 0;
            if (evalator->CheckType() == Type::Bool) {
                bool result = evalator->GetBoolean();
                if (result) {
                    matcher_results[policy_index] = 1;
                }
            } else if (evalator->CheckType() == Type::Float) {
                float result = evalator->GetFloat();
                if (result != 0.0) {
                    matcher_results[policy_index] = 1;
                }
            } else {
                throw CasbinEnforcerException("matcher result should be bool, int or float");
                // return false;
            }

            if (int is_p_eft = p_int_tokens.find("p_eft") != p_int_tokens.end(); is_p_eft) {
                int j = p_int_tokens["p_eft"];
                const std::string& eft = p_vals[j];
                if (eft == "allow") {
                    policy_effects[policy_index] = Effect::Allow;
                } else if (eft == "deny") {
                    policy_effects[policy_index] = Effect::Deny;
                } else {
                    policy_effects[policy_index] = Effect::Indeterminate;
                }
            } else {
                policy_effects[policy_index] = Effect::Allow;
            }

            effect = m_eft->MergeEffects(m_model->m["e"].assertion_map["e"]->value, policy_effects,
                                         matcher_results, policy_index, policy_len, explainIndex);

            if (effect != Effect::Indeterminate) {
                break;
            }
            policy_index++;
        }

        casbin::LogUtil::LogPrint("Rule Results: ", policy_effects);
    } else {
        if (hasEval && p_policy.empty()) {
            throw CasbinEnforcerException("please make sure rule exists in policy when using eval() in matcher");
            // return false;
        }

        policy_effects = std::vector<Effect>(1, Effect::Indeterminate);
        matcher_results = std::vector<float>(1, 1);

        // Push initial value for p in symbol table
        // If p don't in symbol table, the evaluate result will be invalid.
        evalator->Clean(m_model->m["p"], false);
        evalator->InitialObject("p");
        for (const auto& p_token : p_tokens) {
            size_t index = p_token.find("_");
            std::string token = p_token.substr(index + 1);
            evalator->PushObjectString("p", token, "");
        }

        bool isvalid = evalator->Eval(exp_string);
        if (!isvalid) {
            return false;
        }
        bool result = evalator->GetBoolean();

        if (result) {
            policy_effects[0] = Effect::Allow;
        } else {
            policy_effects[0] = Effect::Indeterminate;
        }

        effect = m_eft->MergeEffects(m_model->m["e"].assertion_map["e"]->value, policy_effects,
                                     matcher_results, 0, 1, explainIndex);

        casbin::LogUtil::LogPrint("Rule Results: ", policy_effects);
    }

    PoliciesValues logExplains;

    logExplains.emplace(explains);
    if (explainIndex != -1 && (p_policy.size() > explainIndex)) {
        explains = *std::next(p_policy.begin(), explainIndex);
        logExplains.emplace(explains);
    }

    // effect --> result
    bool result = false;
    if (effect == Effect::Allow) {
        result = true;
    }

    return result;
}

/**
 * Enforcer is the default constructor.
 */
Enforcer ::Enforcer() {
}

/**
 * Enforcer initializes an enforcer with a model file and a policy file.
 *
 * @param model_path the path of the model file.
 * @param policyFile the path of the policy file.
 */
Enforcer ::Enforcer(const std::string& model_path, const std::string& policy_file)
    : Enforcer(model_path, std::make_shared<BatchFileAdapter>(policy_file)) {
}

/**
 * Enforcer initializes an enforcer with a database adapter.
 *
 * @param model_path the path of the model file.
 * @param adapter the adapter.
 */
Enforcer ::Enforcer(const std::string& model_path, std::shared_ptr<Adapter> adapter)
    : Enforcer(std::make_shared<Model>(model_path), adapter) {
    m_model_path = model_path;
}

/**
 * Enforcer initializes an enforcer with a model and a database adapter.
 *
 * @param m the model.
 * @param adapter the adapter.
 */
Enforcer::Enforcer(const std::shared_ptr<Model>& m, std::shared_ptr<Adapter> adapter)
    : m_adapter(adapter), m_watcher(nullptr), m_model(m) {
    m_model->PrintModel();

    this->Initialize();

    if (m_adapter && m_adapter->IsValid())
        this->LoadPolicy();
}

/**
 * Enforcer initializes an enforcer with a model.
 *
 * @param m the model.
 */
Enforcer::Enforcer(const std::shared_ptr<Model>& m)
    : Enforcer(m, NULL) {
}

/**
 * Enforcer initializes an enforcer with a model file.
 *
 * @param model_path the path of the model file.
 */
Enforcer ::Enforcer(const std::string& model_path)
    : Enforcer(model_path, "") {
}

/**
 * Enforcer initializes an enforcer with a model file, a policy file and an enable log flag.
 *
 * @param model_path the path of the model file.
 * @param policyFile the path of the policy file.
 * @param enableLog whether to enable Casbin's log.
 */
Enforcer::Enforcer(const std::string& model_path, const std::string& policy_file, bool enable_log)
    : Enforcer(model_path, std::make_shared<BatchFileAdapter>(policy_file)) {
    this->EnableLog(enable_log);
}

// InitWithFile initializes an enforcer with a model file and a policy file.
void Enforcer::InitWithFile(const std::string& model_path, const std::string& policy_path) {
    std::shared_ptr<Adapter> a = std::make_shared<BatchFileAdapter>(policy_path);
    this->InitWithAdapter(model_path, a);
}

// InitWithAdapter initializes an enforcer with a database adapter.
void Enforcer::InitWithAdapter(const std::string& model_path, std::shared_ptr<Adapter> adapter) {
    std::shared_ptr<Model> m = Model::NewModelFromFile(model_path);

    this->InitWithModelAndAdapter(m, adapter);

    m_model_path = model_path;
}

// InitWithModelAndAdapter initializes an enforcer with a model and a database adapter.
void Enforcer::InitWithModelAndAdapter(const std::shared_ptr<Model>& m, std::shared_ptr<Adapter> adapter) {
    m_adapter = adapter;

    m_model = m;
    m_model->PrintModel();

    this->Initialize();

    // Do not initialize the full policy when using a filtered adapter
    if (m_adapter != NULL && !m_adapter->IsFiltered())
        this->LoadPolicy();
}

void Enforcer::Initialize() {
    this->rm = std::make_shared<DefaultRoleManager>(10);
    m_eft = std::make_shared<DefaultEffector>();
    m_watcher = nullptr;
    m_evalator = nullptr;

    m_enabled = true;
    m_auto_save = true;
    m_auto_build_role_links = true;
    m_auto_notify_watcher = true;
}

/**
 * Destructor of Enforcer
 *
 * @step: Release the memory of Enforcer->m_scope
 */
Enforcer::~Enforcer() {}

// LoadModel reloads the model from the model CONF file.
// Because the policy is attached to a model, so the policy is invalidated and needs
// to be reloaded by calling LoadPolicy().
void Enforcer::LoadModel() {
    m_model = Model::NewModelFromFile(m_model_path);

    m_model->PrintModel();

    this->Initialize();
}

// GetModel gets the current model.
std::shared_ptr<Model> Enforcer::GetModel() {
    return m_model;
}

// SetModel sets the current model.
void Enforcer::SetModel(const std::shared_ptr<Model>& m) {
    m_model = m;

    this->Initialize();
}

// GetAdapter gets the current adapter.
std::shared_ptr<Adapter> Enforcer::GetAdapter() {
    return m_adapter;
}

// SetAdapter sets the current adapter.
void Enforcer::SetAdapter(std::shared_ptr<Adapter> adapter) {
    m_adapter = adapter;
}

// SetWatcher sets the current watcher.
void Enforcer::SetWatcher(std::shared_ptr<Watcher> watcher) {
    m_watcher = watcher;
    auto func = [&, this](std::string str) {
        this->LoadPolicy();
    };
    watcher->SetUpdateCallback(func);
}

// SetWatcher sets the current evaluator.
void Enforcer::SetEvaluator(std::shared_ptr<IEvaluator> evaluator) {
    this->m_evalator = evaluator;
}

// GetRoleManager gets the current role manager.
std::shared_ptr<RoleManager> Enforcer ::GetRoleManager() {
    return this->rm;
}

// SetRoleManager sets the current role manager.
void Enforcer::SetRoleManager(std::shared_ptr<RoleManager>& rm) {
    this->rm = rm;
}

// SetEffector sets the current effector.
void Enforcer::SetEffector(std::shared_ptr<Effector> eft) {
    m_eft = eft;
}

// ClearPolicy clears all policy.
void Enforcer::ClearPolicy() {
    m_model->ClearPolicy();
}

// LoadPolicy reloads the policy from file/database.
void Enforcer::LoadPolicy() {
    // must use base's LoadPolicy to avoid dead lock
    Enforcer::ClearPolicy();
    m_adapter->LoadPolicy(m_model);
    m_model->PrintPolicy();

    if (m_auto_build_role_links) {
        Enforcer::BuildRoleLinks();
    }
}

// LoadFilteredPolicy reloads a filtered policy from file/database.
template <typename Filter>
void Enforcer::LoadFilteredPolicy(Filter filter) {
    this->ClearPolicy();

    std::shared_ptr<FilteredAdapter> filtered_adapter;

    if (m_adapter->IsFiltered())
        filtered_adapter = std::dynamic_pointer_cast<FilteredAdapter>(m_adapter);
    else
        throw CasbinAdapterException("filtered policies are not supported by this adapter");

    filtered_adapter->LoadFilteredPolicy(m_model, filter);

    m_model->PrintPolicy();
    if (m_auto_build_role_links)
        this->BuildRoleLinks();
}

// IsFiltered returns true if the loaded policy has been filtered.
bool Enforcer::IsFiltered() {
    return m_adapter->IsFiltered();
}

// SavePolicy saves the current policy (usually after changed with Casbin API) back to file/database.
void Enforcer::SavePolicy() {
    if (this->IsFiltered())
        throw CasbinEnforcerException("cannot save a filtered policy");

    m_adapter->SavePolicy(m_model);

    if (m_watcher != NULL) {
        if (IsInstanceOf<WatcherEx>(m_watcher.get())) {
            auto watcher = dynamic_cast<WatcherEx*>(m_watcher.get());
            watcher->UpdateForSavePolicy(m_model);
        } else
            return m_watcher->Update();
    }
}

// EnableEnforce changes the enforcing state of Casbin, when Casbin is disabled,
// all access will be allowed by the Enforce() function.
void Enforcer::EnableEnforce(bool enable) {
    m_enabled = enable;
}

// EnableLog changes whether Casbin will log messages to the Logger.
void Enforcer::EnableLog(bool enable) {
    m_log.GetLogger().EnableLog(enable);
}

// EnableAutoNotifyWatcher controls whether to save a policy rule automatically notify the Watcher when it is added or removed.
void Enforcer::EnableAutoNotifyWatcher(bool enable) {
    m_auto_notify_watcher = enable;
}

// EnableAutoSave controls whether to save a policy rule automatically to the adapter when it is added or removed.
void Enforcer::EnableAutoSave(bool auto_save) {
    m_auto_save = auto_save;
}

// EnableAutoBuildRoleLinks controls whether to rebuild the role inheritance relations when a role is added or deleted.
void Enforcer::EnableAutoBuildRoleLinks(bool auto_build_role_links) {
    m_auto_build_role_links = auto_build_role_links;
}

// BuildRoleLinks manually rebuild the role inheritance relations.
void Enforcer::BuildRoleLinks() {
    this->rm->Clear();

    m_model->BuildRoleLinks(this->rm);
}

// BuildIncrementalRoleLinks provides incremental build the role inheritance relations.
void Enforcer::BuildIncrementalRoleLinks(policy_op op, const std::string& p_type, const PoliciesValues& rules) {
    return m_model->BuildIncrementalRoleLinks(this->rm, op, "g", p_type, rules);
}

// Enforce decides whether a "subject" can access a "object" with the operation "action",
// input parameters are usually: (sub, obj, act).
bool Enforcer::Enforce(std::shared_ptr<IEvaluator> evalator) {
    return this->EnforceWithMatcher("", evalator);
}

// Enforce with a vector param,decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
bool Enforcer::Enforce(const DataList& params) {
    return this->EnforceWithMatcher("", params);
}

bool Enforcer::Enforce(const DataVector& params) {
    return this->EnforceWithMatcher("", params);
}

// Enforce with a map param,decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
bool Enforcer::Enforce(const DataMap& params) {
    return this->EnforceWithMatcher("", params);
}

// EnforceWithMatcher use a custom matcher to decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (matcher, sub, obj, act), use model matcher by default when matcher is "".
bool Enforcer::EnforceWithMatcher(const std::string& matcher, std::shared_ptr<IEvaluator> evalator) {
    std::vector<std::string> explain;
    bool result = EnforceExWithMatcher(matcher, evalator, explain);
    return result;
}

// EnforceWithMatcher use a custom matcher to decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (matcher, sub, obj, act), use model matcher by default when matcher is "".
bool Enforcer::EnforceWithMatcher(const std::string& matcher, const DataList& params) {
    std::vector<std::string> explain;
    bool result = EnforceExWithMatcher(matcher, params, explain);
    return result;
}

// EnforceWithMatcher use a custom matcher to decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (matcher, sub, obj, act), use model matcher by default when matcher is "".
bool Enforcer::EnforceWithMatcher(const std::string& matcher, const DataVector& params) {
    std::vector<std::string> explain;
    bool result = EnforceExWithMatcher(matcher, params, explain);
    return result;
}

// EnforceWithMatcher use a custom matcher to decides whether a "subject" can access a "object"
// with the operation "action", input parameters are usually: (matcher, sub, obj, act),
// use model matcher by default when matcher is "".
bool Enforcer::EnforceWithMatcher(const std::string& matcher, const DataMap& params) {
    std::vector<std::string> explain;
    bool result = EnforceExWithMatcher(matcher, params, explain);
    return result;
}

bool Enforcer::EnforceEx(std::shared_ptr<IEvaluator> evalator, std::vector<std::string>& explain) {
    return this->EnforceExWithMatcher("", evalator, explain);
}

bool Enforcer::EnforceEx(const DataList& params, std::vector<std::string>& explain) {
    return this->EnforceExWithMatcher("", params, explain);
}

bool Enforcer::EnforceEx(const DataVector& params, std::vector<std::string>& explain) {
    return this->EnforceExWithMatcher("", params, explain);
}

bool Enforcer::EnforceEx(const DataMap& params, std::vector<std::string>& explain) {
    return this->EnforceExWithMatcher("", params, explain);
}

bool Enforcer::EnforceExWithMatcher(const std::string& matcher, std::shared_ptr<IEvaluator> evalator, std::vector<std::string>& explain) {
    return m_enforce(matcher, explain, evalator);
}

bool Enforcer::EnforceExWithMatcher(const std::string& matcher, const DataList& params, std::vector<std::string>& explain) {
    const std::vector<std::string>& r_tokens = m_model->m["r"].assertion_map["r"]->tokens;

    size_t r_cnt = r_tokens.size();
    size_t cnt = params.size();

    if (cnt != r_cnt)
        return false;

    if (this->m_evalator == nullptr) {
        this->m_evalator = std::make_shared<ExprtkEvaluator>();
    }

    this->m_evalator->InitialObject("r");

    size_t i = 0;

    for (const Data& param : params) {
        if (const auto string_param = std::get_if<std::string>(&param)) {
            this->m_evalator->PushObjectString("r", r_tokens[i].substr(2, r_tokens[i].size() - 2), *string_param);
        } else if (const auto json_param = std::get_if<std::shared_ptr<nlohmann::json>>(&param)) {
            auto data_ptr = *json_param;
            std::string token_name = r_tokens[i].substr(2, r_tokens[i].size() - 2);
            this->m_evalator->PushObjectJson("r", token_name, *data_ptr);
        }
        ++i;
    }

    bool result = m_enforce(matcher, explain, m_evalator);

    return result;
}

bool Enforcer::EnforceExWithMatcher(const std::string& matcher, const DataVector& params, std::vector<std::string>& explain) {
    const std::vector<std::string>& r_tokens = m_model->m["r"].assertion_map["r"]->tokens;

    size_t r_cnt = r_tokens.size();
    size_t cnt = params.size();

    if (cnt != r_cnt)
        return false;

    if (this->m_evalator == nullptr) {
        this->m_evalator = std::make_shared<ExprtkEvaluator>();
    }

    this->m_evalator->InitialObject("r");

    size_t i = 0;

    for (const auto& param : params) {
        if (const auto string_param = std::get_if<std::string>(&param)) {
            this->m_evalator->PushObjectString("r", r_tokens[i].substr(2, r_tokens[i].size() - 2), *string_param);
        } else if (const auto json_param = std::get_if<std::shared_ptr<nlohmann::json>>(&param)) {
            auto data_ptr = *json_param;
            std::string token_name = r_tokens[i].substr(2, r_tokens[i].size() - 2);

            this->m_evalator->PushObjectJson("r", token_name, *data_ptr);
        }

        ++i;
    }

    bool result = m_enforce(matcher, explain, m_evalator);

    return result;
}
bool Enforcer::EnforceExWithMatcher(const std::string& matcher, const DataMap& params, std::vector<std::string>& explain) {
    if (this->m_evalator == nullptr) {
        this->m_evalator = std::make_shared<ExprtkEvaluator>();
    }

    this->m_evalator->InitialObject("r");

    for (auto [param_name, param_data] : params) {
        if (const auto string_param = std::get_if<std::string>(&param_data)) {
            this->m_evalator->PushObjectString("r", param_name, *string_param);
        } else if (const auto json_param = std::get_if<std::shared_ptr<nlohmann::json>>(&param_data)) {
            auto data_ptr = *json_param;
            this->m_evalator->PushObjectJson("r", param_name, *data_ptr);
        }
    }

    bool result = m_enforce(matcher, explain, m_evalator);

    return result;
}

// BatchEnforce enforce in batches
std::vector<bool> Enforcer::BatchEnforce(const std::initializer_list<DataList>& requests) {
    // Initializing an array for storing results with false
    std::vector<bool> results;
    results.reserve(requests.size());
    for (const auto& request : requests) {
        results.push_back(this->Enforce(request));
    }
    return results;
}

// BatchEnforceWithMatcher enforce with matcher in batches
std::vector<bool> Enforcer::BatchEnforceWithMatcher(const std::string& matcher, const std::initializer_list<DataList>& requests) {
    std::vector<bool> results;
    results.reserve(requests.size());
    for (const auto& request : requests) {
        results.push_back(this->EnforceWithMatcher(matcher, request));
    }
    return results;
}

} // namespace casbin

#endif // ENFORCER_CPP
