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

#ifndef CASBIN_CPP_MODEL_ASSERTION
#define CASBIN_CPP_MODEL_ASSERTION

#include <memory>

#include "policy_collection.hpp"
#include "../rbac/role_manager.h"

namespace casbin {

enum policy_op { policy_add, policy_remove };
typedef enum policy_op policy_op;


// Assertion represents an expression in a section of the model.
// For example: r = sub, obj, act
class Assertion {
public:
    std::string key;
    std::string value;
    std::vector<std::string> tokens;
    PoliciesValues policy;
    std::shared_ptr<RoleManager> rm;

    void BuildIncrementalRoleLinks(std::shared_ptr<RoleManager>& rm, policy_op op, const PoliciesValues& rules);

    void BuildRoleLinks(std::shared_ptr<RoleManager>& rm);
};

}; // namespace casbin

#endif
