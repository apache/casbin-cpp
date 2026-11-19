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

/* This is a test file showcasing the workflow of casbin::SyncedEnforcer */

#include <casbin/casbin.h>
#include <gtest/gtest.h>

#include "config_path.h"

namespace {

std::string global_sub;
std::string global_obj;
std::string global_act;
std::string global_domain;

template <typename T>
std::shared_ptr<casbin::IEvaluator> InitializeParams(const std::string& sub, const std::string& obj, const std::string& act) {
    auto evaluator = std::make_shared<T>();
    evaluator->InitialObject("r");

    // Because of "Short String Optimization", these strings's data is in stack.
    // For MSVC compiler, when this stack frame return, these memory will can't access.
    // So we need keep this memory accessiable.
    global_sub = sub;
    global_obj = obj;
    global_act = act;

    evaluator->PushObjectString("r", "sub", global_sub);
    evaluator->PushObjectString("r", "obj", global_obj);
    evaluator->PushObjectString("r", "act", global_act);

    return evaluator;
}

template <typename T>
std::shared_ptr<casbin::IEvaluator> InitializeParamsWithoutUsers(const std::string& obj, const std::string& act) {
    auto evaluator = std::make_shared<T>();
    evaluator->InitialObject("r");

    global_obj = obj;
    global_act = act;
    evaluator->PushObjectString("r", "obj", global_obj);
    evaluator->PushObjectString("r", "act", global_act);
    return evaluator;
}

template <typename T>
std::shared_ptr<casbin::IEvaluator> InitializeParamsWithoutResources(const std::string& sub, const std::string& act) {
    auto evaluator = std::make_shared<T>();
    evaluator->InitialObject("r");

    global_sub = sub;
    global_act = act;
    evaluator->PushObjectString("r", "sub", global_sub);
    evaluator->PushObjectString("r", "act", global_act);
    return evaluator;
}

template <typename T>
std::shared_ptr<casbin::IEvaluator> InitializeParamsWithDomains(const std::string& sub, const std::string& domain, const std::string& obj, const std::string& act) {
    auto evaluator = std::make_shared<T>();
    evaluator->InitialObject("r");

    global_sub = sub;
    global_obj = obj;
    global_act = act;
    global_domain = domain;

    evaluator->PushObjectString("r", "sub", global_sub);
    evaluator->PushObjectString("r", "dom", global_domain);
    evaluator->PushObjectString("r", "obj", global_obj);
    evaluator->PushObjectString("r", "act", global_act);
    return evaluator;
}

void TestSyncFn(casbin::SyncedEnforcer& e, const std::string& sub, const std::string& obj, const std::string& act, bool control) {
    bool response = e.Enforce({sub, obj, act});
    ASSERT_EQ(response, control);
}

TEST(TestEnforcerSynced, TestSync) {
    casbin::SyncedEnforcer e(basic_model_path, basic_policy_path);

    using namespace std::literals::chrono_literals;
    auto time1 = 200ms;
    e.StartAutoLoadPolicy(time1);

    TestSyncFn(e, "alice", "data1", "read", true);
    TestSyncFn(e, "alice", "data1", "write", false);
    TestSyncFn(e, "alice", "data2", "read", false);
    TestSyncFn(e, "alice", "data2", "write", false);
    TestSyncFn(e, "bob", "data1", "read", false);
    TestSyncFn(e, "bob", "data1", "write", false);
    TestSyncFn(e, "bob", "data2", "read", false);
    TestSyncFn(e, "bob", "data2", "write", true);

    std::this_thread::sleep_for(200ms);
    e.StopAutoLoadPolicy();
}

TEST(TestEnforcerSynced, TestStopLoadPolicy) {
    casbin::SyncedEnforcer e(basic_model_path, basic_policy_path);

    using namespace std::literals::chrono_literals;
    std::chrono::duration<int64_t, std::nano> t = 5ms;

    e.StartAutoLoadPolicy(t);

    EXPECT_EQ(e.IsAutoLoadingRunning(), true);

    TestSyncFn(e, "alice", "data1", "read", true);
    TestSyncFn(e, "alice", "data1", "write", false);
    TestSyncFn(e, "alice", "data2", "read", false);
    TestSyncFn(e, "alice", "data2", "write", false);
    TestSyncFn(e, "bob", "data1", "read", false);
    TestSyncFn(e, "bob", "data1", "write", false);
    TestSyncFn(e, "bob", "data2", "read", false);
    TestSyncFn(e, "bob", "data2", "write", true);

    e.StopAutoLoadPolicy();
    std::this_thread::sleep_for(10ms);

    EXPECT_EQ(e.IsAutoLoadingRunning(), false);
}

TEST(TestEnforcerSynced, TestMultiThreadEnforce) {
    casbin::SyncedEnforcer e(basic_model_path, basic_policy_path);

    using namespace std::literals::chrono_literals;
    std::chrono::duration<int64_t, std::nano> t = 5ms;

    e.StartAutoLoadPolicy(t);

    EXPECT_EQ(e.IsAutoLoadingRunning(), true);

    for (int i = 0; i < 100; ++i) {
        std::thread t1([&] { ASSERT_EQ(e.Enforce(casbin::DataList{"alice", "data1", "read"}), true); });
        std::thread t2([&] { ASSERT_EQ(e.Enforce(casbin::DataList{"alice", "data1", "write"}), false); });
        std::thread t3([&] { ASSERT_EQ(e.Enforce(casbin::DataList{"alice", "data2", "read"}), false); });
        std::thread t4([&] { ASSERT_EQ(e.Enforce(casbin::DataList{"alice", "data2", "write"}), false); });
        std::thread t5([&] { ASSERT_EQ(e.Enforce(casbin::DataList{"bob", "data1", "read"}), false); });
        std::thread t6([&] { ASSERT_EQ(e.Enforce(casbin::DataList{"bob", "data1", "write"}), false); });
        std::thread t7([&] { ASSERT_EQ(e.Enforce(casbin::DataList{"bob", "data2", "read"}), false); });
        std::thread t8([&] { ASSERT_EQ(e.Enforce(casbin::DataList{"bob", "data2", "write"}), true); });

        t1.join();
        t2.join();
        t3.join();
        t4.join();
        t5.join();
        t6.join();
        t7.join();
        t8.join();
    }

    for (int i = 0; i < 100; ++i) {
        std::thread t1([&] { ASSERT_EQ(e.Enforce(casbin::DataVector{"alice", "data1", "read"}), true); });
        std::thread t2([&] { ASSERT_EQ(e.Enforce(casbin::DataVector{"alice", "data1", "write"}), false); });
        std::thread t3([&] { ASSERT_EQ(e.Enforce(casbin::DataVector{"alice", "data2", "read"}), false); });
        std::thread t4([&] { ASSERT_EQ(e.Enforce(casbin::DataVector{"alice", "data2", "write"}), false); });
        std::thread t5([&] { ASSERT_EQ(e.Enforce(casbin::DataVector{"bob", "data1", "read"}), false); });
        std::thread t6([&] { ASSERT_EQ(e.Enforce(casbin::DataVector{"bob", "data1", "write"}), false); });
        std::thread t7([&] { ASSERT_EQ(e.Enforce(casbin::DataVector{"bob", "data2", "read"}), false); });
        std::thread t8([&] { ASSERT_EQ(e.Enforce(casbin::DataVector{"bob", "data2", "write"}), true); });

        t1.join();
        t2.join();
        t3.join();
        t4.join();
        t5.join();
        t6.join();
        t7.join();
        t8.join();
    }

    for (int i = 0; i < 100; ++i) {
        std::thread t1([&] { ASSERT_EQ(e.Enforce(casbin::DataMap{{"sub", "alice"}, {"obj", "data1"}, {"act", "read"}}), true); });
        std::thread t2([&] { ASSERT_EQ(e.Enforce(casbin::DataMap{{"sub", "alice"}, {"obj", "data1"}, {"act", "write"}}), false); });
        std::thread t3([&] { ASSERT_EQ(e.Enforce(casbin::DataMap{{"sub", "alice"}, {"obj", "data2"}, {"act", "read"}}), false); });
        std::thread t4([&] { ASSERT_EQ(e.Enforce(casbin::DataMap{{"sub", "alice"}, {"obj", "data2"}, {"act", "write"}}), false); });
        std::thread t5([&] { ASSERT_EQ(e.Enforce(casbin::DataMap{{"sub", "bob"}, {"obj", "data1"}, {"act", "read"}}), false); });
        std::thread t6([&] { ASSERT_EQ(e.Enforce(casbin::DataMap{{"sub", "bob"}, {"obj", "data1"}, {"act", "write"}}), false); });
        std::thread t7([&] { ASSERT_EQ(e.Enforce(casbin::DataMap{{"sub", "bob"}, {"obj", "data2"}, {"act", "read"}}), false); });
        std::thread t8([&] { ASSERT_EQ(e.Enforce(casbin::DataMap{{"sub", "bob"}, {"obj", "data2"}, {"act", "write"}}), true); });

        t1.join();
        t2.join();
        t3.join();
        t4.join();
        t5.join();
        t6.join();
        t7.join();
        t8.join();
    }

    std::mutex mtx; // for evaluator
    for (int i = 0; i < 100; ++i) {
        std::thread t1([&] {
            std::shared_ptr<casbin::IEvaluator> evaluator;
            {
                std::scoped_lock lock(mtx);
                evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data1", "read");
            }
            ASSERT_EQ(e.Enforce(evaluator), true);
        });
        std::thread t2([&] {
            std::shared_ptr<casbin::IEvaluator> evaluator;
            {
                std::scoped_lock lock(mtx);
                evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data1", "write");
            }
            ASSERT_EQ(e.Enforce(evaluator), false);
        });
        std::thread t3([&] {
            std::shared_ptr<casbin::IEvaluator> evaluator;
            {
                std::scoped_lock lock(mtx);
                evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data2", "read");
            }
            ASSERT_EQ(e.Enforce(evaluator), false);
        });
        std::thread t4([&] {
            std::shared_ptr<casbin::IEvaluator> evaluator;
            {
                std::scoped_lock lock(mtx);
                evaluator = InitializeParams<casbin::ExprtkEvaluator>("alice", "data2", "write");
            }
            ASSERT_EQ(e.Enforce(evaluator), false);
        });
        std::thread t5([&] {
            std::shared_ptr<casbin::IEvaluator> evaluator;
            {
                std::scoped_lock lock(mtx);
                evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data1", "read");
            }
            ASSERT_EQ(e.Enforce(evaluator), false);
        });
        std::thread t6([&] {
            std::shared_ptr<casbin::IEvaluator> evaluator;
            {
                std::scoped_lock lock(mtx);
                evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data1", "write");
            }
            ASSERT_EQ(e.Enforce(evaluator), false);
        });
        std::thread t7([&] {
            std::shared_ptr<casbin::IEvaluator> evaluator;
            {
                std::scoped_lock lock(mtx);
                evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data2", "read");
            }
            ASSERT_EQ(e.Enforce(evaluator), false);
        });
        std::thread t8([&] {
            std::shared_ptr<casbin::IEvaluator> evaluator;
            {
                std::scoped_lock lock(mtx);
                evaluator = InitializeParams<casbin::ExprtkEvaluator>("bob", "data2", "write");
            }
            ASSERT_EQ(e.Enforce(evaluator), true);
        });

        t1.join();
        t2.join();
        t3.join();
        t4.join();
        t5.join();
        t6.join();
        t7.join();
        t8.join();
    }

    e.StopAutoLoadPolicy();
    std::this_thread::sleep_for(10ms);

    EXPECT_EQ(e.IsAutoLoadingRunning(), false);
}

TEST(TestEnforcerSynced, TestMultiThreadBatchEnforce) {
    casbin::SyncedEnforcer e(basic_model_path, basic_policy_path);

    using namespace std::literals::chrono_literals;
    std::chrono::duration<int64_t, std::nano> t = 5ms;

    e.StartAutoLoadPolicy(t);

    EXPECT_EQ(e.IsAutoLoadingRunning(), true);

    for (int i = 0; i < 100; ++i) {
        std::thread t1([&] {
            std::vector<bool> expect_result{true, false, false, false};
            ASSERT_EQ(e.BatchEnforce({{"alice", "data1", "read"}, {"alice", "data1", "write"}, {"alice", "data2", "read"}, {"alice", "data2", "write"}}), expect_result);
        });

        std::thread t2([&] {
            std::vector<bool> expect_result{false, false, false, true};
            ASSERT_EQ(e.BatchEnforce({{"bob", "data1", "read"}, {"bob", "data1", "write"}, {"bob", "data2", "read"}, {"bob", "data2", "write"}}), expect_result);
        });

        std::thread t3([&] {
            std::vector<bool> expect_result{true, false, false, false};
            ASSERT_EQ(e.BatchEnforce({{"alice", "data1", "read"}, {"alice", "data1", "write"}, {"bob", "data1", "read"}, {"bob", "data1", "write"}}), expect_result);
        });

        std::thread t4([&] {
            std::vector<bool> expect_result{false, false, false, true};
            ASSERT_EQ(e.BatchEnforce({{"alice", "data2", "read"}, {"alice", "data2", "write"}, {"bob", "data2", "read"}, {"bob", "data2", "write"}}), expect_result);
        });

        t1.join();
        t2.join();
        t3.join();
        t4.join();
    }

    e.StopAutoLoadPolicy();
    std::this_thread::sleep_for(10ms);

    EXPECT_EQ(e.IsAutoLoadingRunning(), false);
}

void testSyncedEnforcerGetPolicy(casbin::SyncedEnforcer& e, PoliciesVector expected) {
    auto myRes = e.GetPolicy();
    PoliciesVector actual;
    for (auto it = myRes.begin(); it != myRes.end(); ++it) {
        actual.push_back(*it);
    }
    std::sort(actual.begin(), actual.end());
    std::sort(expected.begin(), expected.end());
    ASSERT_EQ(expected, actual);
}

TEST(TestSyncedEnforcer, GetPolicy) {
    casbin::SyncedEnforcer e(basic_model_path, basic_policy_path);

    PoliciesVector expected_policy = {
        {"alice", "data1", "read"},
        {"bob", "data2", "write"},
    };

    testSyncedEnforcerGetPolicy(e, expected_policy);
}



} // namespace
