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

#ifndef CASBIN_CPP_RBAC_DEFAULT_ROLE_MANAGER
#define CASBIN_CPP_RBAC_DEFAULT_ROLE_MANAGER

#include <unordered_map>

#include "casbin/pch.h"
#include "casbin/rbac/role_manager.h"

namespace casbin {

typedef bool (*MatchingFunc)(const std::string&, const std::string&);

/**
 * Role represents the data structure for a role in RBAC.
 */
class Role {
private:
    std::vector<Role*> roles;

public:
    std::string name;

    static std::unique_ptr<Role> NewRole(const std::string& name);

    void AddRole(Role* role);

    void DeleteRole(Role* role);

    bool HasRole(std::string name, int hierarchy_level);

    bool HasDirectRole(std::string name);

    std::string ToString();

    std::vector<std::string> GetRoles();
};

class DefaultRoleManager : public RoleManager {
private:
    std::unordered_map<std::string, std::unique_ptr<Role>> all_roles;
    bool has_pattern;
    int max_hierarchy_level;
    MatchingFunc matching_func;

    bool HasRole(std::string name);

    Role* CreateRole(const std::string& name);

public:
    /**
     * DefaultRoleManager is the constructor for creating an instance of the
     * default RoleManager implementation.
     *
     * @param max_hierarchy_level the maximized allowed RBAC hierarchy level.
     */
    DefaultRoleManager(int max_hierarchy_level);

    // e.BuildRoleLinks must be called after AddMatchingFunc().
    //
    // example: e.GetRoleManager().(*defaultrolemanager.RoleManager).AddMatchingFunc('matcher', util.KeyMatch)
    void AddMatchingFunc(MatchingFunc fn);

    /**
     * clear clears all stored data and resets the role manager to the initial state.
     */
    void Clear();

    // AddLink adds the inheritance link between role: name1 and role: name2.
    // aka role: name1 inherits role: name2.
    // domain is a prefix to the roles.
    void AddLink(std::string name1, std::string name2, std::vector<std::string> domain = {});

    /**
     * deleteLink deletes the inheritance link between role: name1 and role: name2.
     * aka role: name1 does not inherit role: name2 any more.
     * domain is a prefix to the roles.
     */
    void DeleteLink(std::string name1, std::string name2, std::vector<std::string> domain = {});

    /**
     * hasLink determines whether role: name1 inherits role: name2.
     * domain is a prefix to the roles.
     */
    bool HasLink(std::string name1, std::string name2, std::vector<std::string> domain = {});

    /**
     * getRoles gets the roles that a subject inherits.
     * domain is a prefix to the roles.
     */
    std::vector<std::string> GetRoles(std::string name, std::vector<std::string> domain = {});

    std::vector<std::string> GetUsers(std::string name, std::vector<std::string> domain = {});

    /**
     * printRoles prints all the roles to log.
     */
    void PrintRoles();
};

}; // namespace casbin

#endif