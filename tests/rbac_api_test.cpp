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

TEST(TestRBACAPI, TestRoleAPI) {
    casbin::Enforcer e(rbac_model_path, rbac_policy_path);

    ASSERT_TRUE(casbin::ArrayEquals({"data2_admin"}, e.GetRolesForUser("alice")));
    ASSERT_TRUE(casbin::ArrayEquals({}, e.GetRolesForUser("bob")));
    ASSERT_TRUE(casbin::ArrayEquals({}, e.GetRolesForUser("data2_admin")));
    ASSERT_TRUE(casbin::ArrayEquals({}, e.GetRolesForUser("non_exist")));

    ASSERT_FALSE(e.HasRoleForUser("alice", "data1_admin"));
    ASSERT_TRUE(e.HasRoleForUser("alice", "data2_admin"));

    e.AddRoleForUser("alice", "data1_admin");

    ASSERT_TRUE(casbin::ArrayEquals({"data1_admin", "data2_admin"}, e.GetRolesForUser("alice")));
    ASSERT_TRUE(casbin::ArrayEquals({}, e.GetRolesForUser("bob")));
    ASSERT_TRUE(casbin::ArrayEquals({}, e.GetRolesForUser("data2_admin")));

    e.DeleteRoleForUser("alice", "data1_admin");

    ASSERT_TRUE(casbin::ArrayEquals({"data2_admin"}, e.GetRolesForUser("alice")));
    ASSERT_TRUE(casbin::ArrayEquals({}, e.GetRolesForUser("bob")));
    ASSERT_TRUE(casbin::ArrayEquals({}, e.GetRolesForUser("data2_admin")));

    e.DeleteRolesForUser("alice");

    ASSERT_TRUE(casbin::ArrayEquals({}, e.GetRolesForUser("alice")));
    ASSERT_TRUE(casbin::ArrayEquals({}, e.GetRolesForUser("bob")));
    ASSERT_TRUE(casbin::ArrayEquals({}, e.GetRolesForUser("data2_admin")));

    e.AddRoleForUser("alice", "data1_admin");
    e.DeleteUser("alice");

    ASSERT_TRUE(casbin::ArrayEquals({}, e.GetRolesForUser("alice")));
    ASSERT_TRUE(casbin::ArrayEquals({}, e.GetRolesForUser("bob")));
    ASSERT_TRUE(casbin::ArrayEquals({}, e.GetRolesForUser("data2_admin")));

    e.AddRoleForUser("alice", "data2_admin");

    ASSERT_FALSE(e.Enforce({"alice", "data1", "read"}));
    ASSERT_FALSE(e.Enforce({"alice", "data1", "write"}));
    ASSERT_TRUE(e.Enforce({"alice", "data2", "read"}));
    ASSERT_TRUE(e.Enforce({"alice", "data2", "write"}));
    ASSERT_FALSE(e.Enforce({"bob", "data1", "read"}));
    ASSERT_FALSE(e.Enforce({"bob", "data1", "write"}));
    ASSERT_FALSE(e.Enforce({"bob", "data2", "read"}));
    ASSERT_TRUE(e.Enforce({"bob", "data2", "write"}));

    e.DeleteRole("data2_admin");

    ASSERT_FALSE(e.Enforce({"alice", "data1", "read"}));
    ASSERT_FALSE(e.Enforce({"alice", "data1", "write"}));
    ASSERT_FALSE(e.Enforce({"alice", "data2", "read"}));
    ASSERT_FALSE(e.Enforce({"alice", "data2", "write"}));
    ASSERT_FALSE(e.Enforce({"bob", "data1", "read"}));
    ASSERT_FALSE(e.Enforce({"bob", "data1", "write"}));
    ASSERT_FALSE(e.Enforce({"bob", "data2", "read"}));
    ASSERT_TRUE(e.Enforce({"bob", "data2", "write"}));
}

TEST(TestRBACAPI, TestEnforcer_AddRolesForUser) {
    casbin::Enforcer e(rbac_model_path, rbac_policy_path);

    e.AddRolesForUser("alice", {"data1_admin", "data2_admin", "data3_admin"});
    ASSERT_TRUE(casbin::ArrayEquals({"data1_admin", "data2_admin", "data3_admin"}, e.GetRolesForUser("alice")));

    ASSERT_TRUE(e.Enforce({"alice", "data1", "read"}));
    ASSERT_TRUE(e.Enforce({"alice", "data2", "read"}));
    ASSERT_TRUE(e.Enforce({"alice", "data2", "write"}));
}

void TestGetPermissions(casbin::Enforcer& e, const std::string& name, const PoliciesValues& res) {
    PoliciesValues my_res = e.GetPermissionsForUser(name);
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

TEST(TestRBACAPI, TestPermissionAPI) {
    casbin::Enforcer e(basic_without_resources_model_path, basic_without_resources_policy_path);

    ASSERT_TRUE(e.Enforce({"alice", "read"}));
    ASSERT_FALSE(e.Enforce({"alice", "write"}));
    ASSERT_FALSE(e.Enforce({"bob", "read"}));
    ASSERT_TRUE(e.Enforce({"bob", "write"}));

    TestGetPermissions(e, "alice", PoliciesValues({{"alice", "read"}}));
    TestGetPermissions(e, "bob", PoliciesValues({{"bob", "write"}}));

    ASSERT_TRUE(e.HasPermissionForUser("alice", {"read"}));
    ASSERT_FALSE(e.HasPermissionForUser("alice", {"write"}));
    ASSERT_FALSE(e.HasPermissionForUser("bob", {"read"}));
    ASSERT_TRUE(e.HasPermissionForUser("bob", {"write"}));

    ASSERT_TRUE(e.DeletePermission({"read"}));

    ASSERT_FALSE(e.Enforce({"alice", "read"}));
    ASSERT_FALSE(e.Enforce({"alice", "write"}));
    ASSERT_FALSE(e.Enforce({"bob", "read"}));
    ASSERT_TRUE(e.Enforce({"bob", "write"}));

    ASSERT_TRUE(e.AddPermissionForUser("bob", {"read"}));

    ASSERT_FALSE(e.Enforce({"alice", "read"}));
    ASSERT_FALSE(e.Enforce({"alice", "write"}));
    ASSERT_TRUE(e.Enforce({"bob", "read"}));
    ASSERT_TRUE(e.Enforce({"bob", "write"}));

    ASSERT_TRUE(e.DeletePermissionForUser("bob", {"read"}));

    ASSERT_FALSE(e.Enforce({"alice", "read"}));
    ASSERT_FALSE(e.Enforce({"alice", "write"}));
    ASSERT_FALSE(e.Enforce({"bob", "read"}));
    ASSERT_TRUE(e.Enforce({"bob", "write"}));

    // TODO: DeletePermissionsForUser this api don't work
    ASSERT_TRUE(e.DeletePermissionsForUser("bob"));

    ASSERT_FALSE(e.Enforce({"alice", "read"}));
    ASSERT_FALSE(e.Enforce({"alice", "write"}));
    ASSERT_FALSE(e.Enforce({"bob", "read"}));
    ASSERT_FALSE(e.Enforce({"bob", "write"}));
}

TEST(TestRBACAPI, TestImplicitRoleAPI) {
    casbin::Enforcer e(rbac_model_path, rbac_with_hierarchy_policy_path);

    TestGetPermissions(e, "alice", PoliciesValues({{"alice", "data1", "read"}}));
    TestGetPermissions(e, "bob", PoliciesValues({{"bob", "data2", "write"}}));

    ASSERT_TRUE(casbin::ArrayEquals(std::vector<std::string>{"admin", "data1_admin", "data2_admin"}, e.GetImplicitRolesForUser("alice")));
    ASSERT_TRUE(casbin::ArrayEquals(std::vector<std::string>{}, e.GetImplicitRolesForUser("bob")));

    e = casbin::Enforcer(rbac_with_pattern_model_path, rbac_with_pattern_policy_path);

    dynamic_cast<casbin::DefaultRoleManager*>(e.GetRoleManager().get())->AddMatchingFunc(casbin::KeyMatch);

    ASSERT_TRUE(casbin::ArrayEquals(std::vector<std::string>{"/book/1/2/3/4/5", "pen_admin", "/book/*", "book_group"}, e.GetImplicitRolesForUser("cathy")));
    ASSERT_TRUE(casbin::ArrayEquals(std::vector<std::string>{"/book/1/2/3/4/5", "pen_admin"}, e.GetRolesForUser("cathy")));
}

void TestGetImplicitPermissions(casbin::Enforcer& e, const std::string& name, const PoliciesValues& res) {
    PoliciesValues my_res = e.GetImplicitPermissionsForUser(name);
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

void TestGetImplicitPermissionsWithDomain(casbin::Enforcer& e, const std::string& name, const std::string& domain, const PoliciesValues& res) {
    PoliciesValues my_res = e.GetImplicitPermissionsForUser(name, {domain});
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

TEST(TestRBACAPI, TestImplicitPermissionAPI) {
    casbin::Enforcer e(rbac_model_path, rbac_with_hierarchy_policy_path);

    TestGetPermissions(e, "alice", PoliciesValues({{"alice", "data1", "read"}}));
    TestGetPermissions(e, "bob", PoliciesValues({{"bob", "data2", "write"}}));

    TestGetImplicitPermissions(e, "alice",
                               PoliciesValues({{"alice", "data1", "read"}, {"data1_admin", "data1", "read"}, {"data1_admin", "data1", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}}));
    TestGetImplicitPermissions(e, "bob", PoliciesValues({{"bob", "data2", "write"}}));
}

TEST(TestRBACAPI, TestImplicitPermissionAPIWithDomain) {
    casbin::Enforcer e(rbac_with_domains_model_path, rbac_with_hierarchy_with_domains_policy_path);
    TestGetImplicitPermissionsWithDomain(e, "alice", "domain1", PoliciesValues({{"alice", "domain1", "data2", "read"}, {"role:reader", "domain1", "data1", "read"}, {"role:writer", "domain1", "data1", "write"}}));
}

TEST(TestRBACAPI, TestImplicitUserAPI) {
    casbin::Enforcer e(rbac_model_path, rbac_with_hierarchy_policy_path);

    ASSERT_TRUE(casbin::ArrayEquals({"alice"}, e.GetImplicitUsersForPermission({"data1", "read"})));
    ASSERT_TRUE(casbin::ArrayEquals({"alice"}, e.GetImplicitUsersForPermission({"data1", "write"})));
    ASSERT_TRUE(casbin::ArrayEquals({"alice"}, e.GetImplicitUsersForPermission({"data2", "read"})));
    ASSERT_TRUE(casbin::ArrayEquals({"alice", "bob"}, e.GetImplicitUsersForPermission({"data2", "write"})));

    e.ClearPolicy();
    e.AddPolicy({"admin", "data1", "read"});
    e.AddPolicy({"bob", "data1", "read"});
    e.AddPolicies(PoliciesValues({{"tom", "data1", "read"}, {"john", "data1", "read"}}));
    e.AddGroupingPolicy({"alice", "admin"});

    ASSERT_TRUE(casbin::ArrayEquals({"alice", "bob", "tom", "john"}, e.GetImplicitUsersForPermission({"data1", "read"})));
}

} // namespace
