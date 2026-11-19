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

#ifndef CASBIN_CPP_PERSIST_FILE_ADAPTER_BATCH_FILE_ADAPTER
#define CASBIN_CPP_PERSIST_FILE_ADAPTER_BATCH_FILE_ADAPTER

#include "../batch_adapter.h"
#include "./file_adapter.h"

namespace casbin {

class BatchFileAdapter : public BatchAdapter, public FileAdapter {
public:
    // NewAdapter is the constructor for Adapter.
    BatchFileAdapter(std::string file_path);

    static std::shared_ptr<BatchFileAdapter> NewBatchFileAdapter(std::string file_path);

    void AddPolicies(std::string sec, std::string p_type, PoliciesValues rules);

    void RemovePolicies(std::string sec, std::string p_type, PoliciesValues rules);
};

} // namespace casbin

#endif