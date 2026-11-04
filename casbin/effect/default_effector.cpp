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

#ifndef DEFAULT_EFFECTOR_CPP
#define DEFAULT_EFFECTOR_CPP

#include "casbin/effect/default_effector.h"
#include "casbin/exception/unsupported_operation_exception.h"

namespace casbin {

/**
 * MergeEffects merges all matching results collected by the enforcer into a single decision.
 */
Effect DefaultEffector::MergeEffects(const std::string& expr, const std::vector<Effect>& effects, const std::vector<float>& matches, int policyIndex, int policyLength, int& explainIndex) {
    Effect result = Effect::Indeterminate;
    explainIndex = -1;

    if (expr == "some(where (p.eft == allow))") { // AllowOverrideEffect
        if (matches[policyIndex] == 0) {
            return result;
        }

        // only check the current policyIndex
        if (effects[policyIndex] == Effect::Allow) {
            result = Effect::Allow;
            explainIndex = policyIndex;
            return result;
        }
    } else if (expr == "!some(where (p.eft == deny))") { // DenyOverrideEffect
        // only check the current policyIndex
        if (matches[policyIndex] != 0 && effects[policyIndex] == Effect::Deny) {
            result = Effect::Deny;
            explainIndex = policyIndex;
            return result;
        }

        // if no deny rules are matched  at last, then allow
        if (policyIndex == policyLength - 1) {
            result = Effect::Allow;
            return result;
        }
    } else if (expr == "some(where (p.eft == allow)) && !some(where (p.eft == deny))") { // AllowAndDenyEffect
        // short-circuit if matched deny rule
        if (matches[policyIndex] != 0 && effects[policyIndex] == Effect::Deny) {
            result = Effect::Deny;
            // set hit rule to the (first) matched deny rule
            explainIndex = policyIndex;
            return result;
        }

        // short-circuit some effects in the middle
        if (policyIndex < policyLength - 1) {
            // choose not to short-circuit
            return result;
        }

        // merge all effects at last
        for (int i = 0; i < effects.size(); ++i) {
            if (matches[i] == 0) {
                continue;
            }

            if (effects[i] == Effect::Allow) {
                result = Effect::Allow;
                // set hit rule to first matched allow rule
                explainIndex = i;
                return result;
            }
        }

    } else if (expr == "priority(p.eft) || deny") { // PriorityEffect
        // reverse merge, short-circuit may be earlier
        for (int i = effects.size() - 1; i >= 0; --i) {
            if (matches[i] == 0) {
                continue;
            }

            if (effects[i] != Effect::Indeterminate) {
                if (effects[i] == Effect::Allow) {
                    result = Effect::Allow;
                } else {
                    result = Effect::Deny;
                }
                explainIndex = i;
                return result;
            }
        }

    } else {
        throw UnsupportedOperationException("unsupported effect");
    }

    return result;
}

} // namespace casbin

#endif // DEFAULT_EFFECTOR_CPP
