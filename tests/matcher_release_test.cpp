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
#include <random>
#include <regex>
#include <string>
#include <thread>
#include <vector>

#include "casbin/util/built_in_functions.h"
#include "casbin/util/ticker.h"

namespace {

// Reference the regex-only behavior preceding the fast-path change. Keep this
// independent of the production helper and its compiled-pattern cache.
std::string Replace(std::string text, const std::string& from, const std::string& to) {
    std::size_t at = 0;
    while ((at = text.find(from, at)) != std::string::npos) {
        text.replace(at, from.size(), to);
        at += to.size();
    }
    return text;
}

bool ReferenceMatch(const std::string& key, const std::string& pattern, bool colon) {
    std::string value = Replace(pattern, "/*", "/.*");
    value = std::regex_replace(value, std::regex(colon ? "(.*?):[^/]+(.*?)" : "(.*?)\\{[^/]+?\\}(.*?)"),
                               "$1[^/]+$2");
    value = Replace(Replace(value, "{", "\\{"), "}", "\\}");
    if (colon && value == "*")
        value = "(.*)";
    return std::regex_match(key, std::regex("^" + value + "$"));
}

TEST(ReleaseMatchers, PlainPathsWildcardAndLineTerminators) {
    for (const auto& key : {"/foo", "/foo/", "/foo/bar", "/foobar", "/foo/x\n", "/foo/x\r", "", "/"}) {
        for (const auto& pattern : {"", "/", "/foo", "/foo/*", "/*"}) {
            SCOPED_TRACE(std::string(key) + " against " + pattern);
            EXPECT_EQ(casbin::KeyMatch2(key, pattern), ReferenceMatch(key, pattern, true));
            EXPECT_EQ(casbin::KeyMatch3(key, pattern), ReferenceMatch(key, pattern, false));
            EXPECT_EQ(casbin::KeyMatch4(key, pattern), ReferenceMatch(key, pattern, false));
        }
    }
}

TEST(ReleaseMatchers, SeededDifferentialAgainstRegexOnly) {
    std::mt19937 rng(1680);
    const std::vector<std::string> patterns = {"/a", "/a/*", "/:id", "/a/:id", "/{id}", "/a/{id}",
                                               "/a/[0-9]+", "/a/(b|c)", "/a/.*", "/a/b?", "/a/\\.", "/*"};
    const std::string alphabet = "abc012/.:_\r\n";
    for (int trial = 0; trial < 2500; ++trial) {
        std::string key = "/";
        for (unsigned count = rng() % 15; count != 0; --count)
            key += alphabet[rng() % alphabet.size()];
        const auto& pattern = patterns[rng() % patterns.size()];
        SCOPED_TRACE(key + " against " + pattern);
        EXPECT_EQ(casbin::KeyMatch2(key, pattern), ReferenceMatch(key, pattern, true));
        EXPECT_EQ(casbin::KeyMatch3(key, pattern), ReferenceMatch(key, pattern, false));
    }
}

TEST(ReleaseMatchers, CacheEvictionRepeatedTokensAndThreads) {
    std::atomic<bool> correct{true};
    std::vector<std::thread> threads;
    for (int worker = 0; worker < 4; ++worker) {
        threads.emplace_back([&correct, worker] {
            for (int index = 0; index < 1100; ++index) {
                const std::string value = std::to_string(worker) + "-" + std::to_string(index);
                const std::string pattern = "/" + value + "/[a-z]+";
                if (!casbin::RegexMatch("/" + value + "/ok", pattern) ||
                    casbin::RegexMatch("/" + value + "/12", pattern) ||
                    !casbin::KeyMatch4("/1/child/1", "/{id}/child/{id}") ||
                    casbin::KeyMatch4("/1/child/2", "/{id}/child/{id}"))
                    correct = false;
            }
        });
    }
    for (auto& thread : threads)
        thread.join();
    EXPECT_TRUE(correct);
    EXPECT_TRUE(casbin::KeyMatch5("/parent/child?mode=1", "/parent/{id}"));
    EXPECT_FALSE(casbin::KeyMatch5("/wrong?mode=1", "/parent/{id}"));
    EXPECT_THROW(casbin::RegexMatch("/foo", "["), std::regex_error);
    EXPECT_TRUE(casbin::RegexMatch("/foo", "/foo"));
}

TEST(ReleaseTicker, SlowCallbacksDoNotOverlapAndCanRestart) {
    std::atomic<int> active{0};
    std::atomic<int> calls{0};
    std::atomic<bool> overlap{false};
    casbin::Ticker ticker([&] {
        if (active.fetch_add(1) != 0)
            overlap = true;
        ++calls;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        --active;
    }, std::chrono::milliseconds(1));
    ticker.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    ticker.stop();
    EXPECT_FALSE(overlap);
    EXPECT_EQ(active.load(), 0);
    EXPECT_GE(calls.load(), 1);
    const auto before = calls.load();
    ticker.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
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

} // namespace
