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

#ifndef CASBIN_CPP_EFFECT_EFFECTOR
#define CASBIN_CPP_EFFECT_EFFECTOR

#include <string>
#include <vector>

#include "effect.h"

namespace casbin {

/**
 * Effector is the abstract class for Casbin effectors.
 */
class Effector {
public:
    /**
     * MergeEffects merges all matching results collected by the enforcer into a single decision.
     *
     * @param expr the expression of [policy_effect].
     * @param effects the effects of all matched rules.
     * @param matches the matcher results of all matched rules.
     * @param policyIndex the index of current policy.
     * @param policyLength the length of the policy.
     * @param explainIndex the index of explain
     * @return the final effect.
     *      @retval Effect::Allow
     *      @retval Effect::Deny
     *      @retval Effect::Indeterminate (need further judgment)
     */
    virtual Effect MergeEffects(const std::string& expr, const std::vector<Effect>& effects, const std::vector<float>& matches, int policyIndex, int policyLength, int& explainIndex) = 0;
};

} // namespace casbin

#endif