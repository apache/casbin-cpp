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

#ifndef RBAC_API_WITH_DOMAINS_CPP
#define RBAC_API_WITH_DOMAINS_CPP

#include "casbin/enforcer.h"

namespace casbin {

// GetUsersForRoleInDomain gets the users that has a role inside a domain. Add by Gordon
std::vector<std::string> Enforcer ::GetUsersForRoleInDomain(const std::string& name, const std::string& domain) {
    std::vector<std::string> domains{domain};
    std::vector<std::string> res = m_model->m["g"].assertion_map["g"]->rm->GetUsers(name, domains);
    return res;
}

// GetRolesForUserInDomain gets the roles that a user has inside a domain.
std::vector<std::string> Enforcer ::GetRolesForUserInDomain(const std::string& name, const std::string& domain) {
    std::vector<std::string> domains{domain};
    std::vector<std::string> res = m_model->m["g"].assertion_map["g"]->rm->GetRoles(name, domains);
    return res;
}

// GetPermissionsForUserInDomain gets permissions for a user or role inside a domain.
PoliciesValues Enforcer ::GetPermissionsForUserInDomain(const std::string& user, const std::string& domain) {
    std::vector<std::string> field_values{user, domain};
    return this->GetFilteredPolicy(0, field_values);
}

// AddRoleForUserInDomain adds a role for a user inside a domain.
// Returns false if the user already has the role (aka not affected).
bool Enforcer ::AddRoleForUserInDomain(const std::string& user, const std::string& role, const std::string& domain) {
    std::vector<std::string> params{user, role, domain};
    return this->AddGroupingPolicy(params);
}

// DeleteRoleForUserInDomain deletes a role for a user inside a domain.
// Returns false if the user does not have the role (aka not affected).
bool Enforcer ::DeleteRoleForUserInDomain(const std::string& user, const std::string& role, const std::string& domain) {
    std::vector<std::string> params{user, role, domain};
    return this->RemoveGroupingPolicy(params);
}

} // namespace casbin

#endif // RBAC_API_WITH_DOMAINS_CPP
