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

#ifndef CASBIN_CPP_PERSIST_ADAPTER
#define CASBIN_CPP_PERSIST_ADAPTER

#include <string>
#include <vector>

#include "casbin/model/model.h"

namespace casbin {

// SplitPolicyLine splits a CSV policy line into fields, unquoting double-quoted fields.
std::vector<std::string> SplitPolicyLine(const std::string& line);

// LoadPolicyLine loads a text line as a policy rule to model.
void LoadPolicyLine(const std::string& line, const std::shared_ptr<Model>& model);

/**
 * Adapter is the interface for Casbin adapters.
 */
class Adapter {
public:
    bool filtered;

    virtual ~Adapter() = default;

    /**
     * LoadPolicy loads all policy rules from the storage.
     *
     * @param model the model.
     */
    virtual void LoadPolicy(const std::shared_ptr<Model>& model) = 0;

    /**
     * SavePolicy saves all policy rules to the storage.
     *
     * @param model the model.
     */
    virtual void SavePolicy(const std::shared_ptr<Model>& model) = 0;

    /**
     * AddPolicy adds a policy rule to the storage.
     * This is part of the Auto-Save feature.
     *
     * @param sec the section, "p" or "g".
     * @param p_type the policy type, "p", "p2", .. or "g", "g2", ..
     * @param rule the rule, like (sub, obj, act).
     */
    virtual void AddPolicy(std::string sec, std::string p_type, std::vector<std::string> rule) = 0;

    /**
     * RemovePolicy removes a policy rule from the storage.
     * This is part of the Auto-Save feature.
     *
     * @param sec the section, "p" or "g".
     * @param p_type the policy type, "p", "p2", .. or "g", "g2", ..
     * @param rule the rule, like (sub, obj, act).
     */
    virtual void RemovePolicy(std::string sec, std::string p_type, std::vector<std::string> rule) = 0;

    /**
     * RemoveFilteredPolicy removes policy rules that match the filter from the storage.
     * This is part of the Auto-Save feature.
     *
     * @param sec the section, "p" or "g".
     * @param p_type the policy type, "p", "p2", .. or "g", "g2", ..
     * @param field_index the policy rule's start index to be matched.
     * @param field_values the field values to be matched, value ""
     *                    means not to match this field.
     */
    virtual void RemoveFilteredPolicy(std::string sec, std::string ptype, int field_index, std::vector<std::string> field_values) = 0;

    virtual bool IsFiltered() = 0;

    virtual bool IsValid() = 0;
};

}; // namespace casbin

#endif