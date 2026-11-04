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

#ifndef CASBIN_CPP_PERSIST_WATCHER_EX
#define CASBIN_CPP_PERSIST_WATCHER_EX

#include "casbin/model/model.h"
#include "casbin/persist/watcher.h"

namespace casbin {

// WatcherEx is the strengthen for Casbin watchers.
class WatcherEx : public Watcher {
public:
    // UpdateForAddPolicy calls the update callback of other instances to synchronize their policy.
    // It is called after Enforcer.AddPolicy()
    virtual void UpdateForAddPolicy(std::vector<std::string> params) = 0;

    // UPdateForRemovePolicy calls the update callback of other instances to synchronize their policy.
    // It is called after Enforcer.RemovePolicy()
    virtual void UpdateForRemovePolicy(std::vector<std::string> params) = 0;

    // UpdateForRemoveFilteredPolicy calls the update callback of other instances to synchronize their policy.
    // It is called after Enforcer.RemoveFilteredNamedGroupingPolicy()
    virtual void UpdateForRemoveFilteredPolicy(int field_index, std::vector<std::string> field_values) = 0;

    // UpdateForSavePolicy calls the update callback of other instances to synchronize their policy.
    // It is called after Enforcer.RemoveFilteredNamedGroupingPolicy()
    virtual void UpdateForSavePolicy(const std::shared_ptr<Model>& model) = 0;
};

}; // namespace casbin

#endif