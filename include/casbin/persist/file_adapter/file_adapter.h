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

#ifndef CASBIN_CPP_PERSIST_FILE_ADAPTER_FILE_ADAPTER
#define CASBIN_CPP_PERSIST_FILE_ADAPTER_FILE_ADAPTER

#include "../adapter.h"

namespace casbin {

// Adapter is the file adapter for Casbin.
// It can load policy from file or save policy to file.
class FileAdapter : virtual public Adapter {
public:
    std::string file_path;

    // NewAdapter is the constructor for Adapter.
    FileAdapter(std::string file_path);

    static std::shared_ptr<FileAdapter> NewFileAdapter(std::string file_path);

    // LoadPolicy loads all policy rules from the storage.
    void LoadPolicy(const std::shared_ptr<Model>& model);

    // SavePolicy saves all policy rules to the storage.
    void SavePolicy(const std::shared_ptr<Model>& model);

    void LoadPolicyFile(const std::shared_ptr<Model>& model, std::function<void(std::string, const std::shared_ptr<Model>&)> handler);

    void SavePolicyFile(std::string text);

    // AddPolicy adds a policy rule to the storage.
    void AddPolicy(std::string sec, std::string p_type, std::vector<std::string> rule);

    // RemovePolicy removes a policy rule from the storage.
    void RemovePolicy(std::string sec, std::string p_type, std::vector<std::string> rule);

    // RemoveFilteredPolicy removes policy rules that match the filter from the storage.
    void RemoveFilteredPolicy(std::string sec, std::string p_type, int field_index, std::vector<std::string> field_values);

    // IsFiltered returns true if the loaded policy has been filtered.
    bool IsFiltered();

    // IsValid returns true if the loaded policy is valid.
    bool IsValid();
};

}; // namespace casbin

#endif