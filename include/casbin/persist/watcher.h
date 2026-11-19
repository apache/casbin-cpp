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

#ifndef CASBIN_CPP_PERSIST_WATCHER
#define CASBIN_CPP_PERSIST_WATCHER

#include <string>

namespace casbin {

// Watcher is the interface for Casbin watchers.
class Watcher {
public:
    // SetUpdateCallback sets the callback function that the watcher will call
    // when the policy in DB has been changed by other instances.
    // A classic callback is Enforcer.LoadPolicy().
    template <typename Func>
    void SetUpdateCallback(Func func) {
        return;
    }

    // Update calls the update callback of other instances to synchronize their policy.
    // It is usually called after changing the policy in DB, like Enforcer.SavePolicy(),
    // Enforcer.AddPolicy(), Enforcer.RemovePolicy(), etc.
    virtual void Update() = 0;

    // Close stops and releases the watcher, the callback function will not be called any more.
    virtual void Close() = 0;
};

}; // namespace casbin

#endif