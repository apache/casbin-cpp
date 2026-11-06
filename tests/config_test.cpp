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

/* This is a test file showcasing the workflow of casbin::Config */

#include <casbin/casbin.h>
#include <gtest/gtest.h>

namespace {

std::shared_ptr<casbin::Config> GetTestConfig() { return casbin::Config::NewConfig("../../casbin/config/testdata/testini.ini"); }

TEST(TestConfig, TestDebug) {
    auto config = GetTestConfig();
    EXPECT_EQ(config->GetBool("debug"), true);
}

TEST(TestConfig, TestURL) {
    auto config = GetTestConfig();
    ASSERT_EQ(config->GetString("url"), "act.wiki");
}

TEST(TestConfig, TestRedis) {
    auto config = GetTestConfig();
    std::vector<std::string> values = config->GetStrings("redis::redis.key");
    ASSERT_EQ(std::string("push1"), values[0]);
    ASSERT_EQ(std::string("push2"), values[1]);
}

} // namespace
