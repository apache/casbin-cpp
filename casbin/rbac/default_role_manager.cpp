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

#ifndef DEFAULT_ROLE_MANAGER_CPP
#define DEFAULT_ROLE_MANAGER_CPP

#include "casbin/exception/casbin_rbac_exception.h"
#include "casbin/rbac/default_role_manager.h"

namespace casbin {

std::unique_ptr<Role> Role :: NewRole(const std::string& name) {
    auto role = std::make_unique<Role>();
    role->name = name;
    return role;
}

void Role ::AddRole(Role* role) {
    for (int i = 0; i < this->roles.size(); i++) {
        if (this->roles[i]->name == role->name)
            return;
    }

    this->roles.push_back(role);
}

void Role ::DeleteRole(Role* role) {
    for (int i = 0; i < roles.size(); i++) {
        if (roles[i]->name == role->name)
            roles.erase(roles.begin() + i);
    }
}

bool Role ::HasRole(std::string name, int hierarchy_level) {
    if (this->name == name)
        return true;

    if (hierarchy_level <= 0)
        return false;

    for (int i = 0; i < roles.size(); i++) {
        if (roles[i]->HasRole(name, hierarchy_level - 1))
            return true;
    }

    return false;
}

bool Role ::HasDirectRole(std::string name) {
    for (int i = 0; i < roles.size(); i++) {
        if (roles[i]->name == name)
            return true;
    }

    return false;
}

std::string Role ::ToString() {
    if (this->roles.size() == 0)
        return "";

    std::string names = "";
    if (this->roles.size() != 1)
        names += "(";

    for (int i = 0; i < roles.size(); i++) {
        auto role = roles[i];
        if (i == 0)
            names += role->name;
        else
            names += ", " + role->name;
    }

    if (this->roles.size() != 1)
        names += ")";

    return name + " < " + names;
}

std::vector<std::string> Role ::GetRoles() {
    std::vector<std::string> names;
    for (int i = 0; i < roles.size(); i++)
        names.push_back(roles[i]->name);

    return names;
}

bool DefaultRoleManager ::HasRole(std::string name) {
    bool ok = false;
    if (this->has_pattern) {
        for (auto it = this->all_roles.begin(); it != this->all_roles.end(); it++) {
            if (this->matching_func(name, it->first))
                ok = true;
        }
    } else
        ok = this->all_roles.find(name) != this->all_roles.end();

    return ok;
}

Role* DefaultRoleManager ::CreateRole(const std::string& name) {
    Role* role;
    bool ok = this->all_roles.find(name) != this->all_roles.end();
    if (!ok) {
        all_roles[name] = Role ::NewRole(name);
        role = all_roles[name].get();
    } else
        role = all_roles[name].get();

    if (this->has_pattern) {
        for (auto it = this->all_roles.begin(); it != this->all_roles.end(); it++) {
            if (this->matching_func(name, it->first) && name != it->first) {
                Role* role1 = nullptr;
                bool ok1 = this->all_roles.find(it->first) != this->all_roles.end();
                if (!ok1) {
                    all_roles[it->first] = Role ::NewRole(it->first);
                    role1 = all_roles[it->first].get();
                } else
                    role1 = all_roles[it->first].get();

                role->AddRole(role1);
            }
        }
    }

    return role;
}

/**
 * DefaultRoleManager is the constructor for creating an instance of the
 * default RoleManager implementation.
 *
 * @param max_hierarchy_level the maximized allowed RBAC hierarchy level.
 */
DefaultRoleManager ::DefaultRoleManager(int max_hierarchy_level) {
    this->max_hierarchy_level = max_hierarchy_level;
    this->has_pattern = false;
}

// e.BuildRoleLinks must be called after AddMatchingFunc().
//
// example: e.GetRoleManager().(*defaultrolemanager.RoleManager).AddMatchingFunc('matcher', util.KeyMatch)
void DefaultRoleManager ::AddMatchingFunc(MatchingFunc fn) {
    this->has_pattern = true;
    this->matching_func = fn;
}

/**
 * clear clears all stored data and resets the role manager to the initial state.
 */
void DefaultRoleManager ::Clear() {
    this->all_roles.clear();
}

// AddLink adds the inheritance link between role: name1 and role: name2.
// aka role: name1 inherits role: name2.
// domain is a prefix to the roles.
void DefaultRoleManager ::AddLink(std::string name1, std::string name2, std::vector<std::string> domain) {
    if (domain.size() == 1) {
        name1 = domain[0] + "::" + name1;
        name2 = domain[0] + "::" + name2;
    } else if (domain.size() > 1)
        throw CasbinRBACException("error: domain should be 1 parameter");

    auto role1 = this->CreateRole(name1);
    auto role2 = this->CreateRole(name2);
    role1->AddRole(role2);
}

/**
 * deleteLink deletes the inheritance link between role: name1 and role: name2.
 * aka role: name1 does not inherit role: name2 any more.
 * domain is a prefix to the roles.
 */
void DefaultRoleManager ::DeleteLink(std::string name1, std::string name2, std::vector<std::string> domain) {
    unsigned int domain_length = int(domain.size());
    if (domain_length == 1) {
        name1 = domain[0] + "::" + name1;
        name2 = domain[0] + "::" + name2;
    } else if (domain_length > 1)
        throw CasbinRBACException("error: domain should be 1 parameter");

    if (!HasRole(name1) || !HasRole(name2))
        throw CasbinRBACException("error: name1 or name2 does not exist");

    auto role1 = this->CreateRole(name1);
    auto role2 = this->CreateRole(name2);
    role1->DeleteRole(role2);
}

/**
 * hasLink determines whether role: name1 inherits role: name2.
 * domain is a prefix to the roles.
 */
bool DefaultRoleManager ::HasLink(std::string name1, std::string name2, std::vector<std::string> domain) {
    unsigned int domain_length = int(domain.size());
    if (domain_length == 1) {
        name1 = domain[0] + "::" + name1;
        name2 = domain[0] + "::" + name2;
    } else if (domain_length > 1)
        throw CasbinRBACException("error: domain should be 1 parameter");

    if (!name1.compare(name2))
        return true;
    if (!HasRole(name1) || !HasRole(name2))
        return false;

    auto role1 = this->CreateRole(name1);
    return role1->HasRole(name2, max_hierarchy_level);
}

/**
 * getRoles gets the roles that a subject inherits.
 * domain is a prefix to the roles.
 */
std::vector<std::string> DefaultRoleManager ::GetRoles(std::string name, std::vector<std::string> domain) {
    unsigned int domain_length = int(domain.size());
    if (domain_length == 1)
        name = domain[0] + "::" + name;
    else if (domain_length > 1)
        throw CasbinRBACException("error: domain should be 1 parameter");

    if (!HasRole(name)) {
        std::vector<std::string> roles;
        return roles;
    }

    std::vector<std::string> roles = this->CreateRole(name)->GetRoles();
    if (domain_length == 1) {
        for (int i = 0; i < roles.size(); i++)
            roles[i] = roles[i].substr(domain[0].length() + 2, roles[i].length() - domain[0].length() - 2);
    }

    return roles;
}

std::vector<std::string> DefaultRoleManager ::GetUsers(std::string name, std::vector<std::string> domain) {
    if (domain.size() == 1)
        name = domain[0] + "::" + name;
    else if (domain.size() > 1)
        throw CasbinRBACException("error: domain should be 1 parameter");

    if (!this->HasRole(name))
        throw CasbinRBACException("error: name does not exist");

    std::vector<std::string> names;
    for (auto it = this->all_roles.begin(); it != this->all_roles.end(); it++) {
        auto role = it->second.get();
        if (role->HasDirectRole(name))
            names.push_back(role->name);
    }

    if (domain.size() == 1) {
        for (int i = 0; i < names.size(); i++)
            names[i] = names[i].substr(domain[0].length() + 2, names[i].length() - domain[0].length() - 2);
    }

    return names;
}

/**
 * printRoles prints all the roles to log.
 */
void DefaultRoleManager ::PrintRoles() {
    // DefaultLogger df_logger;
    // df_logger.EnableLog(true);

    // Logger *logger = &df_logger;
    // LogUtil::SetLogger(*logger);

    std::string text = this->all_roles.begin()->second->ToString();
    auto it = this->all_roles.begin();
    it++;
    for (; it != this->all_roles.end(); it++)
        text += ", " + it->second->ToString();
    // LogUtil::LogPrint(text);
}

} // namespace casbin

#endif // DEFAULT_ROLE_MANAGER_CPP
