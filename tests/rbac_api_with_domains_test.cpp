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

/* This is a test file for testing built in functions in casbin */

#include <casbin/casbin.h>
#include <gtest/gtest.h>

#include "config_path.h"

namespace {

TEST(TestRBACAPIWithDomains, TestGetImplicitRolesForDomainUser) {
    casbin::Enforcer e(rbac_with_domains_model_path, rbac_with_hierarchy_with_domains_policy_path);

    // This is only able to retrieve the first level of roles.
    ASSERT_TRUE(casbin::ArrayEquals({"role:global_admin"}, e.GetRolesForUserInDomain("alice", {"domain1"})));

    // Retrieve all inherit roles. It supports domains as well.
    ASSERT_TRUE(casbin::ArrayEquals(std::vector<std::string>{"role:global_admin", "role:reader", "role:writer"}, e.GetImplicitRolesForUser("alice", {"domain1"})));
}

// TestUserAPIWithDomains: Add by Gordon
TEST(TestRBACAPIWithDomains, TestUserAPIWithDomains) {
    casbin::Enforcer e(rbac_with_domains_model_path, rbac_with_domains_policy_path);

    ASSERT_TRUE(casbin::ArrayEquals({"alice"}, e.GetUsersForRole("admin", {"domain1"})));
    ASSERT_TRUE(casbin::ArrayEquals({"alice"}, e.GetUsersForRoleInDomain("admin", {"domain1"})));

    try {
        e.GetUsersForRole("non_exist", {"domain1"});
    } catch (casbin::CasbinRBACException e) {
        ASSERT_TRUE(true);
    }

    try {
        e.GetUsersForRoleInDomain("non_exist", {"domain1"});
    } catch (casbin::CasbinRBACException e) {
        ASSERT_TRUE(true);
    }

    ASSERT_TRUE(casbin::ArrayEquals({"bob"}, e.GetUsersForRole("admin", {"domain2"})));
    ASSERT_TRUE(casbin::ArrayEquals({"bob"}, e.GetUsersForRoleInDomain("admin", {"domain2"})));

    try {
        e.GetUsersForRole("non_exist", {"domain2"});
    } catch (casbin::CasbinRBACException e) {
        ASSERT_TRUE(true);
    }

    try {
        e.GetUsersForRoleInDomain("non_exist", {"domain2"});
    } catch (casbin::CasbinRBACException e) {
        ASSERT_TRUE(true);
    }

    e.DeleteRoleForUserInDomain("alice", "admin", "domain1");
    e.AddRoleForUserInDomain("bob", "admin", "domain1");

    ASSERT_TRUE(casbin::ArrayEquals({"bob"}, e.GetUsersForRole("admin", {"domain1"})));
    ASSERT_TRUE(casbin::ArrayEquals({"bob"}, e.GetUsersForRoleInDomain("admin", {"domain1"})));

    try {
        e.GetUsersForRole("non_exist", {"domain1"});
    } catch (casbin::CasbinRBACException e) {
        ASSERT_TRUE(true);
    }

    try {
        e.GetUsersForRoleInDomain("non_exist", {"domain1"});
    } catch (casbin::CasbinRBACException e) {
        ASSERT_TRUE(true);
    }

    ASSERT_TRUE(casbin::ArrayEquals({"bob"}, e.GetUsersForRole("admin", {"domain2"})));
    ASSERT_TRUE(casbin::ArrayEquals({"bob"}, e.GetUsersForRoleInDomain("admin", {"domain2"})));

    try {
        e.GetUsersForRole("non_exist", {"domain2"});
    } catch (casbin::CasbinRBACException e) {
        ASSERT_TRUE(true);
    }
    try {
        e.GetUsersForRoleInDomain("non_exist", {"domain2"});
    } catch (casbin::CasbinRBACException e) {
        ASSERT_TRUE(true);
    }
}

TEST(TestRBACAPIWithDomains, TestRoleAPIWithDomains) {
    casbin::Enforcer e(rbac_with_domains_model_path, rbac_with_domains_policy_path);

    ASSERT_TRUE(casbin::ArrayEquals({"admin"}, e.GetRolesForUser("alice", {"domain1"})));
    ASSERT_TRUE(casbin::ArrayEquals({"admin"}, e.GetRolesForUserInDomain("alice", {"domain1"})));

    ASSERT_TRUE(casbin::ArrayEquals({}, e.GetRolesForUser("bob", {"domain1"})));
    ASSERT_TRUE(casbin::ArrayEquals({}, e.GetRolesForUserInDomain("bob", {"domain1"})));

    ASSERT_TRUE(casbin::ArrayEquals({}, e.GetRolesForUser("admin", {"domain1"})));
    ASSERT_TRUE(casbin::ArrayEquals({}, e.GetRolesForUserInDomain("admin", {"domain1"})));

    ASSERT_TRUE(casbin::ArrayEquals({}, e.GetRolesForUser("non_exist", {"domain1"})));
    ASSERT_TRUE(casbin::ArrayEquals({}, e.GetRolesForUserInDomain("non_exist", {"domain1"})));

    ASSERT_TRUE(casbin::ArrayEquals({}, e.GetRolesForUser("alice", {"domain2"})));
    ASSERT_TRUE(casbin::ArrayEquals({}, e.GetRolesForUserInDomain("alice", {"domain2"})));

    ASSERT_TRUE(casbin::ArrayEquals({"admin"}, e.GetRolesForUser("bob", {"domain2"})));
    ASSERT_TRUE(casbin::ArrayEquals({"admin"}, e.GetRolesForUserInDomain("bob", {"domain2"})));

    ASSERT_TRUE(casbin::ArrayEquals({}, e.GetRolesForUser("admin", {"domain2"})));
    ASSERT_TRUE(casbin::ArrayEquals({}, e.GetRolesForUserInDomain("admin", {"domain2"})));

    ASSERT_TRUE(casbin::ArrayEquals({}, e.GetRolesForUser("non_exist", {"domain2"})));
    ASSERT_TRUE(casbin::ArrayEquals({}, e.GetRolesForUserInDomain("non_exist", {"domain2"})));

    e.DeleteRoleForUserInDomain("alice", "admin", "domain1");
    e.AddRoleForUserInDomain("bob", "admin", "domain1");

    ASSERT_TRUE(casbin::ArrayEquals({}, e.GetRolesForUser("alice", {"domain1"})));
    ASSERT_TRUE(casbin::ArrayEquals({}, e.GetRolesForUserInDomain("alice", {"domain1"})));

    ASSERT_TRUE(casbin::ArrayEquals({"admin"}, e.GetRolesForUser("bob", {"domain1"})));
    ASSERT_TRUE(casbin::ArrayEquals({"admin"}, e.GetRolesForUserInDomain("bob", {"domain1"})));

    ASSERT_TRUE(casbin::ArrayEquals({}, e.GetRolesForUser("admin", {"domain1"})));
    ASSERT_TRUE(casbin::ArrayEquals({}, e.GetRolesForUserInDomain("admin", {"domain1"})));

    ASSERT_TRUE(casbin::ArrayEquals({}, e.GetRolesForUser("non_exist", {"domain1"})));
    ASSERT_TRUE(casbin::ArrayEquals({}, e.GetRolesForUserInDomain("non_exist", {"domain1"})));

    ASSERT_TRUE(casbin::ArrayEquals({}, e.GetRolesForUser("alice", {"domain2"})));
    ASSERT_TRUE(casbin::ArrayEquals({}, e.GetRolesForUserInDomain("alice", {"domain2"})));

    ASSERT_TRUE(casbin::ArrayEquals({"admin"}, e.GetRolesForUser("bob", {"domain2"})));
    ASSERT_TRUE(casbin::ArrayEquals({"admin"}, e.GetRolesForUserInDomain("bob", {"domain2"})));

    ASSERT_TRUE(casbin::ArrayEquals({}, e.GetRolesForUser("admin", {"domain2"})));
    ASSERT_TRUE(casbin::ArrayEquals({}, e.GetRolesForUserInDomain("admin", {"domain2"})));

    ASSERT_TRUE(casbin::ArrayEquals({}, e.GetRolesForUser("non_exist", {"domain2"})));
    ASSERT_TRUE(casbin::ArrayEquals({}, e.GetRolesForUserInDomain("non_exist", {"domain2"})));
}

void TestGetPermissionsInDomain(casbin::Enforcer& e, const std::string& name, const std::string& domain, const PoliciesValues& res) {
    PoliciesValues my_res = e.GetPermissionsForUserInDomain(name, {domain});
    int count = 0;
    for (auto& my_response : my_res) {
        for (auto& response : res) {
            if (casbin::ArrayEquals(response, my_response)) {
                ++count;
                break;
            }
        }
    }
    ASSERT_EQ(static_cast<int>(res.size()), count);
}

TEST(TestRBACAPIWithDomains, TestPermissionAPIInDomain) {
    casbin::Enforcer e(rbac_with_domains_model_path, rbac_with_domains_policy_path);

    TestGetPermissionsInDomain(e, "alice", "domain1", {});
    TestGetPermissionsInDomain(e, "bob", "domain1", {});
    TestGetPermissionsInDomain(e, "admin", "domain1", PoliciesValues({{"admin", "domain1", "data1", "read"}, {"admin", "domain1", "data1", "write"}}));
    TestGetPermissionsInDomain(e, "non_exist", "domain1", {});

    TestGetPermissionsInDomain(e, "alice", "domain2", {});
    TestGetPermissionsInDomain(e, "bob", "domain2", {});
    TestGetPermissionsInDomain(e, "admin", "domain2", PoliciesValues({{"admin", "domain2", "data2", "read"}, {"admin", "domain2", "data2", "write"}}));
    TestGetPermissionsInDomain(e, "non_exist", "domain2", {});
}

} // namespace
