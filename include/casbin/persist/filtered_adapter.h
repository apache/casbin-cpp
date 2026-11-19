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

#ifndef CASBIN_CPP_PERSIST_ADAPTER_FILTERED
#define CASBIN_CPP_PERSIST_ADAPTER_FILTERED

#include "./adapter.h"

namespace casbin {

// Filter defines the filtering rules for a FilteredAdapter's policy. Empty values
// are ignored, but all others must match the filter.
class Filter {
public:
    std::vector<std::string> P;
    std::vector<std::string> G;
};

// FilteredAdapter is the interface for Casbin adapters supporting filtered policies.
class FilteredAdapter : virtual public Adapter {
public:
    // LoadFilteredPolicy loads only policy rules that match the filter.
    void LoadFilteredPolicy(const std::shared_ptr<Model>& model, Filter* filter);
    // IsFiltered returns true if the loaded policy has been filtered.
    virtual bool IsFiltered() = 0;
};

}; // namespace casbin

#endif