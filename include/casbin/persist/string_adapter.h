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

#ifndef CASBIN_CPP_PERSIST_STRING_ADAPTER_STRING_ADAPTER
#define CASBIN_CPP_PERSIST_STRING_ADAPTER_STRING_ADAPTER

#include "./adapter.h"

namespace casbin {

// Adapter is the string adapter for Casbin.
// It can load policy from string buffer or save policy to string buffer.
class StringAdapter : virtual public Adapter {
public:
    std::string line;

    // NewAdapter is the constructor for Adapter.
    StringAdapter(std::string line);

    static std::shared_ptr<StringAdapter> NewStringAdapter(std::string line);

    // LoadPolicy loads all policy rules from the string buffer.
    void LoadPolicy(const std::shared_ptr<Model>& model);

    // SavePolicy saves all policy rules to the string buffer.
    void SavePolicy(const std::shared_ptr<Model>& model);

    // AddPolicy adds a policy rule to the string buffer.
    void AddPolicy(std::string sec, std::string p_type, std::vector<std::string> rule);

    // RemovePolicy removes a policy rule from the string buffer.
    void RemovePolicy(std::string sec, std::string p_type, std::vector<std::string> rule);

    // RemoveFilteredPolicy removes policy rules that match the filter from the string buffer.
    void RemoveFilteredPolicy(std::string sec, std::string p_type, int field_index, std::vector<std::string> field_values);

    // IsFiltered returns true if the loaded policy has been filtered.
    bool IsFiltered();

    // IsValid returns true if the loaded policy is valid.
    bool IsValid();
};

}; // namespace casbin

#endif