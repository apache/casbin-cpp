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

#ifndef CASBIN_CPP_PERSIST_FILE_ADAPTER_FILTERED_ADAPTER
#define CASBIN_CPP_PERSIST_FILE_ADAPTER_FILTERED_ADAPTER

#include "../filtered_adapter.h"
#include "file_adapter.h"

namespace casbin {

class FilteredFileAdapter : public FileAdapter, public FilteredAdapter {
private:
    static bool filterLine(std::string line, Filter* filter);

    static bool filterWords(std::vector<std::string> line, std::vector<std::string> filter);

    void loadFilteredPolicyFile(const std::shared_ptr<Model>& model, Filter* filter, std::function<void(std::string, const std::shared_ptr<Model>&)> handler);

public:
    // NewFilteredAdapter is the constructor for FilteredAdapter.
    FilteredFileAdapter(std::string file_path);

    // LoadPolicy loads all policy rules from the storage.
    void LoadPolicy(const std::shared_ptr<Model>& model);

    // LoadFilteredPolicy loads only policy rules that match the filter.
    void LoadFilteredPolicy(const std::shared_ptr<Model>& model, Filter* filter);

    // IsFiltered returns true if the loaded policy has been filtered.
    bool IsFiltered();

    // SavePolicy saves all policy rules to the storage.
    void SavePolicy(const std::shared_ptr<Model>& model);
};

}; // namespace casbin

#endif