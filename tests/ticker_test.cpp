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

#include <gtest/gtest.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <future>
#include <mutex>
#include <thread>

#include "casbin/enforcer_synced.h"
#include "casbin/util/ticker.h"

namespace {

TEST(ReleaseTicker, SlowCallbacksDoNotOverlapAndCanRestart) {
    std::atomic<int> active{0};
    std::atomic<int> calls{0};
    std::atomic<bool> overlap{false};
    std::mutex progressMutex;
    std::condition_variable progress;
    casbin::Ticker ticker([&] {
        if (active.fetch_add(1) != 0)
            overlap = true;
        {
            std::lock_guard<std::mutex> lock(progressMutex);
            ++calls;
        }
        progress.notify_one();
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        --active;
    }, std::chrono::milliseconds(1));
    const auto waitForCalls = [&](int minimum) {
        std::unique_lock<std::mutex> lock(progressMutex);
        return progress.wait_for(lock, std::chrono::seconds(5), [&] { return calls.load() >= minimum; });
    };
    ticker.start();
    // Wait for observable callback progress, including on busy CI runners.
    EXPECT_TRUE(waitForCalls(3));
    ticker.stop();
    EXPECT_FALSE(overlap);
    EXPECT_EQ(active.load(), 0);
    EXPECT_GE(calls.load(), 1);
    const auto before = calls.load();
    ticker.start();
    EXPECT_TRUE(waitForCalls(before + 1));
    ticker.stop();
    ticker.stop();
    EXPECT_GT(calls.load(), before);
    EXPECT_FALSE(overlap);
}

TEST(ReleaseTicker, StopInterruptsLongWait) {
    std::promise<void> entered;
    casbin::Ticker ticker([&] { entered.set_value(); }, std::chrono::seconds(10));
    ticker.start();
    auto ready = entered.get_future().wait_for(std::chrono::seconds(2));
    EXPECT_EQ(ready, std::future_status::ready);
    const auto before = std::chrono::steady_clock::now();
    ticker.stop();
    EXPECT_LT(std::chrono::steady_clock::now() - before, std::chrono::seconds(2));
}

TEST(ReleaseTicker, AutoLoadStopIsSafeBeforeStart) {
    casbin::SyncedEnforcer enforcer;
    enforcer.StopAutoLoadPolicy();
    enforcer.StopAutoLoadPolicy();
    EXPECT_FALSE(enforcer.IsAutoLoadingRunning());
}

} // namespace
