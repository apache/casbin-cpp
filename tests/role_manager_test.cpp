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

namespace {

void TestRole(casbin::DefaultRoleManager& rm, const std::string& name1, const std::string& name2, bool res) {
    bool my_res = rm.HasLink(name1, name2);
    ASSERT_EQ(res, my_res);
}

void TestDomainRole(casbin::DefaultRoleManager& rm, const std::string& name1, const std::string& name2, const std::vector<std::string>& domain, bool res) {
    bool my_res = rm.HasLink(name1, name2, domain);

    ASSERT_EQ(res, my_res);
}

TEST(TestRoleManager, TestRole) {
    casbin::DefaultRoleManager rm(3);
    rm.AddLink("u1", "g1");
    rm.AddLink("u2", "g1");
    rm.AddLink("u3", "g2");
    rm.AddLink("u4", "g2");
    rm.AddLink("u4", "g3");
    rm.AddLink("g1", "g3");

    // Current role inheritance tree:
    //             g3    g2
    //            /  \  /  \
    //          g1    u4    u3
    //         /  \
    //       u1    u2

    TestRole(rm, "u1", "g1", true);
    TestRole(rm, "u1", "g2", false);
    TestRole(rm, "u1", "g3", true);
    TestRole(rm, "u2", "g1", true);
    TestRole(rm, "u2", "g2", false);
    TestRole(rm, "u2", "g3", true);
    TestRole(rm, "u3", "g1", false);
    TestRole(rm, "u3", "g2", true);
    TestRole(rm, "u3", "g3", false);
    TestRole(rm, "u4", "g1", false);
    TestRole(rm, "u4", "g2", true);
    TestRole(rm, "u4", "g3", true);

    rm.DeleteLink("g1", "g3");
    rm.DeleteLink("u4", "g2");

    // Current role inheritance tree after deleting the links:
    //             g3    g2
    //               \     \
    //          g1    u4    u3
    //         /  \
    //       u1    u2

    TestRole(rm, "u1", "g1", true);
    TestRole(rm, "u1", "g2", false);
    TestRole(rm, "u1", "g3", false);
    TestRole(rm, "u2", "g1", true);
    TestRole(rm, "u2", "g2", false);
    TestRole(rm, "u2", "g3", false);
    TestRole(rm, "u3", "g1", false);
    TestRole(rm, "u3", "g2", true);
    TestRole(rm, "u3", "g3", false);
    TestRole(rm, "u4", "g1", false);
    TestRole(rm, "u4", "g2", false);
    TestRole(rm, "u4", "g3", true);
}

TEST(TestRoleManager, TestDomainRole) {
    casbin::DefaultRoleManager rm(3);
    std::vector<std::string> domain1 = {"domain1"};
    std::vector<std::string> domain2 = {"domain2"};

    rm.AddLink("u1", "g1", domain1);
    rm.AddLink("u2", "g1", domain1);

    rm.AddLink("u3", "admin", domain2);
    rm.AddLink("u4", "admin", domain2);

    rm.AddLink("u4", "admin", domain1);
    rm.AddLink("g1", "admin", domain1);

    // Current role inheritance tree:
    //       domain1:admin    domain2:admin
    //            /       \  /       \
    //      domain1:g1     u4         u3
    //         /  \
    //       u1    u2

    TestDomainRole(rm, "u1", "g1", domain1, true);
    TestDomainRole(rm, "u1", "g1", domain2, false);
    TestDomainRole(rm, "u1", "admin", domain1, true);
    TestDomainRole(rm, "u1", "admin", domain2, false);

    TestDomainRole(rm, "u2", "g1", domain1, true);
    TestDomainRole(rm, "u2", "g1", domain2, false);
    TestDomainRole(rm, "u2", "admin", domain1, true);
    TestDomainRole(rm, "u2", "admin", domain2, false);

    TestDomainRole(rm, "u3", "g1", domain1, false);
    TestDomainRole(rm, "u3", "g1", domain2, false);
    TestDomainRole(rm, "u3", "admin", domain1, false);
    TestDomainRole(rm, "u3", "admin", domain2, true);

    TestDomainRole(rm, "u4", "g1", domain1, false);
    TestDomainRole(rm, "u4", "g1", domain2, false);
    TestDomainRole(rm, "u4", "admin", domain1, true);
    TestDomainRole(rm, "u4", "admin", domain2, true);

    rm.DeleteLink("g1", "admin", domain1);
    rm.DeleteLink("u4", "admin", domain2);

    // Current role inheritance tree after deleting the links:
    //       domain1:admin    domain2:admin
    //                    \          \
    //      domain1:g1     u4         u3
    //         /  \
    //       u1    u2

    TestDomainRole(rm, "u1", "g1", domain1, true);
    TestDomainRole(rm, "u1", "g1", domain2, false);
    TestDomainRole(rm, "u1", "admin", domain1, false);
    TestDomainRole(rm, "u1", "admin", domain2, false);

    TestDomainRole(rm, "u2", "g1", domain1, true);
    TestDomainRole(rm, "u2", "g1", domain2, false);
    TestDomainRole(rm, "u2", "admin", domain1, false);
    TestDomainRole(rm, "u2", "admin", domain2, false);

    TestDomainRole(rm, "u3", "g1", domain1, false);
    TestDomainRole(rm, "u3", "g1", domain2, false);
    TestDomainRole(rm, "u3", "admin", domain1, false);
    TestDomainRole(rm, "u3", "admin", domain2, true);

    TestDomainRole(rm, "u4", "g1", domain1, false);
    TestDomainRole(rm, "u4", "g1", domain2, false);
    TestDomainRole(rm, "u4", "admin", domain1, true);
    TestDomainRole(rm, "u4", "admin", domain2, false);
}

TEST(TestRoleManager, TestClear) {
    casbin::DefaultRoleManager rm(3);
    rm.AddLink("u1", "g1");
    rm.AddLink("u2", "g1");
    rm.AddLink("u3", "g2");
    rm.AddLink("u4", "g2");
    rm.AddLink("u4", "g3");
    rm.AddLink("g1", "g3");

    // Current role inheritance tree:
    //             g3    g2
    //            /  \  /  \
    //          g1    u4    u3
    //         /  \
    //       u1    u2

    rm.Clear();

    // All data is cleared.
    // No role inheritance now.

    TestRole(rm, "u1", "g1", false);
    TestRole(rm, "u1", "g2", false);
    TestRole(rm, "u1", "g3", false);
    TestRole(rm, "u2", "g1", false);
    TestRole(rm, "u2", "g2", false);
    TestRole(rm, "u2", "g3", false);
    TestRole(rm, "u3", "g1", false);
    TestRole(rm, "u3", "g2", false);
    TestRole(rm, "u3", "g3", false);
    TestRole(rm, "u4", "g1", false);
    TestRole(rm, "u4", "g2", false);
    TestRole(rm, "u4", "g3", false);
}

} // namespace
