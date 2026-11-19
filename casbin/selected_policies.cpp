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

#include "casbin/selected_policies.h"


std::vector<std::string> SelectedPolicies::requestedPolicy()
{
    auto policy_tokens = model->m["r"].assertion_map["r"]->tokens;
    std::vector<std::string> ret;
    ret.reserve(policy_tokens.size());

    auto request_tokens_values_map = evaluator->requestValues();

    for(const auto& p : policy_tokens)
    {
        auto token = p.substr(2, p.size() - 2); // "p_token" -> "token"
        if (auto it = request_tokens_values_map.find(token); it != request_tokens_values_map.end()) {
            ret.emplace_back(it->second);
            continue;
        }
        throw std::logic_error("request and policy tokens names missmatch:" + p);
    }
    return ret;
}

SelectedPolicies::SelectedPolicies(
    const std::shared_ptr<casbin::IEvaluator>& evaluator_, const std::string& matcher_, std::shared_ptr<casbin::Model> model_)
    : evaluator(evaluator_), model(model_), selected_policies() {}


PoliciesValues& SelectedPolicies::operator*() {
    auto& policies = model->m["p"].assertion_map["p"]->policy;
    if (policies.is_hash()) {
        if (auto policy_it = policies.find(requestedPolicy()); policy_it != policies.end()) {
        	selected_policies = PoliciesValues({*policy_it});
	}
        return selected_policies;
    } 
    return policies;
}

