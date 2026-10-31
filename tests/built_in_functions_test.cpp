/*
 * Copyright 2021 The casbin Authors. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * This is a test file for testing built in functions in casbin
 */

#include <casbin/casbin.h>
#include <gtest/gtest.h>

namespace {

void TestKeyMatchFn(std::string key1, std::string key2, bool res) {
    auto evaluator = casbin::ExprtkEvaluator();
    auto func = casbin::ExprtkFunctionFactory::GetExprtkFunction(casbin::ExprtkFunctionType::KeyMatch, 2);
    evaluator.AddFunction("keyMatch", func);
    evaluator.AddIdentifier("key1", key1);
    evaluator.AddIdentifier("key2", key2);
    evaluator.Eval("keyMatch(key1, key2)");
    bool my_res = evaluator.GetBoolean();
    EXPECT_EQ(res, my_res);
}

TEST(TestBuiltInFunctions, TestKeyMatch) {
    TestKeyMatchFn("/foo", "/foo", true);
    TestKeyMatchFn("/foo", "/foo*", true);
    TestKeyMatchFn("/foo", "/foo/*", false);
    TestKeyMatchFn("/foo/bar", "/foo", false);
    TestKeyMatchFn("/foo/bar", "/foo*", true);
    TestKeyMatchFn("/foo/bar", "/foo/*", true);
    TestKeyMatchFn("/foobar", "/foo", false);
    TestKeyMatchFn("/foobar", "/foo*", true);
    TestKeyMatchFn("/foobar", "/foo/*", false);
}

void testKeyGetFn(std::string key1, std::string key2, std::string res) {
    //    std::string my_res = casbin::KeyGet(key1, key2);
    //    ASSERT_EQ(res, my_res);

    auto evaluator = casbin::ExprtkEvaluator();
    auto func = casbin::ExprtkFunctionFactory::GetExprtkFunction(casbin::ExprtkFunctionType::KeyGet, 2);
    evaluator.AddFunction("keyGet", func);
    evaluator.AddIdentifier("key1", key1);
    evaluator.AddIdentifier("key2", key2);
    evaluator.EnableGet("key_get_result");
    bool ok = evaluator.Eval("key_get_result := keyGet(key1, key2);");
    ASSERT_EQ(true, ok);
    std::string actual_result = evaluator.GetString();
    ASSERT_EQ(res, actual_result);
}

TEST(TestBuiltInFunctions, testKeyGet) {
    testKeyGetFn("/foo", "/foo", "");
    testKeyGetFn("/foo", "/foo*", "");
    testKeyGetFn("/foo", "/foo/*", "");
    testKeyGetFn("/foo/bar", "/foo", "");
    testKeyGetFn("/foo/bar", "/foo*", "/bar");
    testKeyGetFn("/foo/bar", "/foo/*", "bar");
    testKeyGetFn("/foobar", "/foo", "");
    testKeyGetFn("/foobar", "/foo*", "bar");
    testKeyGetFn("/foobar", "/foo/*", "");
}

void TestKeyMatch2Fn(std::string key1, std::string key2, bool res) {
    auto evaluator = casbin::ExprtkEvaluator();
    auto func = casbin::ExprtkFunctionFactory::GetExprtkFunction(casbin::ExprtkFunctionType::KeyMatch2, 2);
    evaluator.AddFunction("keyMatch2", func);
    evaluator.AddIdentifier("key1", key1);
    evaluator.AddIdentifier("key2", key2);
    evaluator.Eval("keyMatch2(key1, key2)");
    bool my_res = evaluator.GetBoolean();
    EXPECT_EQ(res, my_res);
}

TEST(TestBuiltInFunctions, TestKeyMatch2) {
    TestKeyMatch2Fn("/foo", "/foo", true);
    TestKeyMatch2Fn("/foo", "/foo*", true);
    TestKeyMatch2Fn("/foo", "/foo/*", false);
    TestKeyMatch2Fn("/foo/bar", "/foo", false);
    TestKeyMatch2Fn("/foo/bar", "/foo*", false); // different with KeyMatch.
    TestKeyMatch2Fn("/foo/bar", "/foo/*", true);
    TestKeyMatch2Fn("/foobar", "/foo", false);
    TestKeyMatch2Fn("/foobar", "/foo*", false); // different with KeyMatch.
    TestKeyMatch2Fn("/foobar", "/foo/*", false);

    TestKeyMatch2Fn("/", "/:resource", false);
    TestKeyMatch2Fn("/resource1", "/:resource", true);
    TestKeyMatch2Fn("/myid", "/:id/using/:resId", false);
    TestKeyMatch2Fn("/myid/using/myresid", "/:id/using/:resId", true);

    TestKeyMatch2Fn("/proxy/myid", "/proxy/:id/*", false);
    TestKeyMatch2Fn("/proxy/myid/", "/proxy/:id/*", true);
    TestKeyMatch2Fn("/proxy/myid/res", "/proxy/:id/*", true);
    TestKeyMatch2Fn("/proxy/myid/res/res2", "/proxy/:id/*", true);
    TestKeyMatch2Fn("/proxy/myid/res/res2/res3", "/proxy/:id/*", true);
    TestKeyMatch2Fn("/proxy/", "/proxy/:id/*", false);

    TestKeyMatch2Fn("/alice", "/:id", true);
    TestKeyMatch2Fn("/alice/all", "/:id/all", true);
    TestKeyMatch2Fn("/alice", "/:id/all", false);
    TestKeyMatch2Fn("/alice/all", "/:id", false);

    TestKeyMatch2Fn("/alice/all", "/:/all", false);
}

void testKeyGet2Fn(std::string key1, std::string key2, std::string path_var, std::string res) {
    //    std::string my_res = casbin::KeyGet2(key1, key2, path_var);
    //    ASSERT_EQ(res, my_res);

    auto evaluator = casbin::ExprtkEvaluator();
    auto func = casbin::ExprtkFunctionFactory::GetExprtkFunction(casbin::ExprtkFunctionType::KeyGet2, 3);
    evaluator.AddFunction("keyGet2", func);
    evaluator.AddIdentifier("key1", key1);
    evaluator.AddIdentifier("key2", key2);
    evaluator.AddIdentifier("path_var", path_var);
    evaluator.EnableGet("key_get_result");
    bool ok = evaluator.Eval("key_get_result := keyGet2(key1, key2, path_var);");
    ASSERT_EQ(true, ok);
    std::string actual_result = evaluator.GetString();
    ASSERT_EQ(res, actual_result);
}

TEST(TestBuiltInFunctions, testKeyGet2) {
    testKeyGet2Fn("/foo", "/foo", "id", "");
    testKeyGet2Fn("/foo", "/foo*", "id", "");
    testKeyGet2Fn("/foo", "/foo/*", "id", "");
    testKeyGet2Fn("/foo/bar", "/foo", "id", "");
    testKeyGet2Fn("/foo/bar", "/foo*", "id", "");
    testKeyGet2Fn("/foo/bar", "/foo/*", "id", "");
    testKeyGet2Fn("/foobar", "/foo", "id", "");
    testKeyGet2Fn("/foobar", "/foo*", "id", "");
    testKeyGet2Fn("/foobar", "/foo/*", "id", "");

    testKeyGet2Fn("/", "/:resource", "resource", "");
    testKeyGet2Fn("/resource1", "/:resource", "resource", "resource1");
    testKeyGet2Fn("/myid", "/:id/using/:resId", "id", "");
    testKeyGet2Fn("/myid/using/myresid", "/:id/using/:resId", "id", "myid");
    testKeyGet2Fn("/myid/using/myresid", "/:id/using/:resId", "resId", "myresid");

    testKeyGet2Fn("/proxy/myid", "/proxy/:id/*", "id", "");
    testKeyGet2Fn("/proxy/myid/", "/proxy/:id/*", "id", "myid");
    testKeyGet2Fn("/proxy/myid/res", "/proxy/:id/*", "id", "myid");
    testKeyGet2Fn("/proxy/myid/res/res2", "/proxy/:id/*", "id", "myid");
    testKeyGet2Fn("/proxy/myid/res/res2/res3", "/proxy/:id/*", "id", "myid");
    testKeyGet2Fn("/proxy/myid/res/res2/res3", "/proxy/:id/res/*", "id", "myid");
    testKeyGet2Fn("/proxy/", "/proxy/:id/*", "id", "");

    testKeyGet2Fn("/alice", "/:id", "id", "alice");
    testKeyGet2Fn("/alice/all", "/:id/all", "id", "alice");
    testKeyGet2Fn("/alice", "/:id/all", "id", "");
    testKeyGet2Fn("/alice/all", "/:id", "id", "");

    testKeyGet2Fn("/alice/all", "/:/all", "", "");
}

void TestKeyMatch3Fn(std::string key1, std::string key2, bool res) {
    auto evaluator = casbin::ExprtkEvaluator();
    auto func = casbin::ExprtkFunctionFactory::GetExprtkFunction(casbin::ExprtkFunctionType::KeyMatch3, 2);
    evaluator.AddFunction("keyMatch3", func);
    evaluator.AddIdentifier("key1", key1);
    evaluator.AddIdentifier("key2", key2);
    evaluator.Eval("keyMatch3(key1, key2)");
    bool my_res = evaluator.GetBoolean();
    EXPECT_EQ(res, my_res);
}

TEST(TestBuiltInFunctions, TestKeyMatch3) {
    // keyMatch3() is similar with KeyMatch2(), except using "/proxy/{id}" instead of "/proxy/:id".
    TestKeyMatch3Fn("/foo", "/foo", true);
    TestKeyMatch3Fn("/foo", "/foo*", true);
    TestKeyMatch3Fn("/foo", "/foo/*", false);
    TestKeyMatch3Fn("/foo/bar", "/foo", false);
    TestKeyMatch3Fn("/foo/bar", "/foo*", false);
    TestKeyMatch3Fn("/foo/bar", "/foo/*", true);
    TestKeyMatch3Fn("/foobar", "/foo", false);
    TestKeyMatch3Fn("/foobar", "/foo*", false);
    TestKeyMatch3Fn("/foobar", "/foo/*", false);

    TestKeyMatch3Fn("/", "/{resource}", false);
    TestKeyMatch3Fn("/resource1", "/{resource}", true);
    TestKeyMatch3Fn("/myid", "/{id}/using/{resId}", false);
    TestKeyMatch3Fn("/myid/using/myresid", "/{id}/using/{resId}", true);

    TestKeyMatch3Fn("/proxy/myid", "/proxy/{id}/*", false);
    TestKeyMatch3Fn("/proxy/myid/", "/proxy/{id}/*", true);
    TestKeyMatch3Fn("/proxy/myid/res", "/proxy/{id}/*", true);
    TestKeyMatch3Fn("/proxy/myid/res/res2", "/proxy/{id}/*", true);
    TestKeyMatch3Fn("/proxy/myid/res/res2/res3", "/proxy/{id}/*", true);
    TestKeyMatch3Fn("/proxy/", "/proxy/{id}/*", false);

    TestKeyMatch3Fn("/myid/using/myresid", "/{id/using/{resId}", false);
}

void testKeyGet3Fn(std::string key1, std::string key2, std::string path_var, std::string res) {
    //    std::string my_res = casbin::KeyGet3(key1, key2, path_var);
    //    ASSERT_EQ(res, my_res);

    auto evaluator = casbin::ExprtkEvaluator();
    auto func = casbin::ExprtkFunctionFactory::GetExprtkFunction(casbin::ExprtkFunctionType::KeyGet3, 3);
    evaluator.AddFunction("keyGet3", func);
    evaluator.AddIdentifier("key1", key1);
    evaluator.AddIdentifier("key2", key2);
    evaluator.AddIdentifier("path_var", path_var);
    evaluator.EnableGet("key_get_result");
    bool ok = evaluator.Eval("key_get_result := keyGet3(key1, key2, path_var);");
    ASSERT_EQ(true, ok);
    std::string actual_result = evaluator.GetString();
    ASSERT_EQ(res, actual_result);
}

TEST(TestBuiltInFunctions, testKeyGet3) {
    // KeyGet3() is similar with KeyGet2(), except using "/proxy/{id}" instead of "/proxy/:id".
    testKeyGet3Fn("/foo", "/foo", "id", "");
    testKeyGet3Fn("/foo", "/foo*", "id", "");
    testKeyGet3Fn("/foo", "/foo/*", "id", "");
    testKeyGet3Fn("/foo/bar", "/foo", "id", "");
    testKeyGet3Fn("/foo/bar", "/foo*", "id", "");
    testKeyGet3Fn("/foo/bar", "/foo/*", "id", "");
    testKeyGet3Fn("/foobar", "/foo", "id", "");
    testKeyGet3Fn("/foobar", "/foo*", "id", "");
    testKeyGet3Fn("/foobar", "/foo/*", "id", "");

    testKeyGet3Fn("/", "/{resource}", "resource", "");
    testKeyGet3Fn("/resource1", "/{resource}", "resource", "resource1");
    testKeyGet3Fn("/myid", "/{id}/using/{resId}", "id", "");
    testKeyGet3Fn("/myid/using/myresid", "/{id}/using/{resId}", "id", "myid");
    testKeyGet3Fn("/myid/using/myresid", "/{id}/using/{resId}", "resId", "myresid");

    testKeyGet3Fn("/proxy/myid", "/proxy/{id}/*", "id", "");
    testKeyGet3Fn("/proxy/myid/", "/proxy/{id}/*", "id", "myid");
    testKeyGet3Fn("/proxy/myid/res", "/proxy/{id}/*", "id", "myid");
    testKeyGet3Fn("/proxy/myid/res/res2", "/proxy/{id}/*", "id", "myid");
    testKeyGet3Fn("/proxy/myid/res/res2/res3", "/proxy/{id}/*", "id", "myid");
    testKeyGet3Fn("/proxy/", "/proxy/{id}/*", "id", "");

    testKeyGet3Fn("/api/group1_group_name/project1_admin/info", "/api/{proj}_admin/info", "proj", "");
    testKeyGet3Fn("/{id/using/myresid", "/{id/using/{resId}", "resId", "myresid");
    testKeyGet3Fn("/{id/using/myresid/status}", "/{id/using/{resId}/status}", "resId", "myresid");

    testKeyGet3Fn("/proxy/myid/res/res2/res3", "/proxy/{id}/*/{res}", "res", "res3");
    testKeyGet3Fn("/api/project1_admin/info", "/api/{proj}_admin/info", "proj", "project1");
    testKeyGet3Fn("/api/group1_group_name/project1_admin/info", "/api/{g}_{gn}/{proj}_admin/info", "g", "group1");
    testKeyGet3Fn("/api/group1_group_name/project1_admin/info", "/api/{g}_{gn}/{proj}_admin/info", "gn", "group_name");
    testKeyGet3Fn("/api/group1_group_name/project1_admin/info", "/api/{g}_{gn}/{proj}_admin/info", "proj", "project1");
}

void TestKeyMatch4Fn(std::string key1, std::string key2, bool res) {
    auto evaluator = casbin::ExprtkEvaluator();
    auto func = casbin::ExprtkFunctionFactory::GetExprtkFunction(casbin::ExprtkFunctionType::KeyMatch4, 2);
    evaluator.AddFunction("keyMatch4", func);
    evaluator.AddIdentifier("key1", key1);
    evaluator.AddIdentifier("key2", key2);
    evaluator.Eval("keyMatch4(key1, key2)");
    bool my_res = evaluator.GetBoolean();
    EXPECT_EQ(res, my_res);
}

TEST(TestBuiltInFunctions, TestKeyMatch4) {
    TestKeyMatch4Fn("/parent/123/child/123", "/parent/{id}/child/{id}", true);
    TestKeyMatch4Fn("/parent/123/child/456", "/parent/{id}/child/{id}", false);

    TestKeyMatch4Fn("/parent/123/child/123", "/parent/{id}/child/{another_id}", true);
    TestKeyMatch4Fn("/parent/123/child/456", "/parent/{id}/child/{another_id}", true);

    TestKeyMatch4Fn("/parent/123/child/123/book/123", "/parent/{id}/child/{id}/book/{id}", true);
    TestKeyMatch4Fn("/parent/123/child/123/book/456", "/parent/{id}/child/{id}/book/{id}", false);
    TestKeyMatch4Fn("/parent/123/child/456/book/123", "/parent/{id}/child/{id}/book/{id}", false);
    TestKeyMatch4Fn("/parent/123/child/456/book/", "/parent/{id}/child/{id}/book/{id}", false);
    TestKeyMatch4Fn("/parent/123/child/456", "/parent/{id}/child/{id}/book/{id}", false);

    TestKeyMatch4Fn("/parent/123/child/123", "/parent/{i/d}/child/{i/d}", false);
}

void TestKeyMatch5Fn(std::string key1, std::string key2, bool res) {
    auto evaluator = casbin::ExprtkEvaluator();
    auto func = casbin::ExprtkFunctionFactory::GetExprtkFunction(casbin::ExprtkFunctionType::KeyMatch5, 2);
    evaluator.AddFunction("keyMatch5", func);
    evaluator.AddIdentifier("key1", key1);
    evaluator.AddIdentifier("key2", key2);
    evaluator.Eval("keyMatch5(key1, key2)");
    bool my_res = evaluator.GetBoolean();
    EXPECT_EQ(res, my_res);
}

TEST(TestBuiltInFunctions, TestKeyMatch5) {
    TestKeyMatch5Fn("/parent/child?status=1&type=2", "/parent/child", true);
    TestKeyMatch5Fn("/parent?status=1&type=2", "/parent/child", false);

    TestKeyMatch5Fn("/parent/child/?status=1&type=2", "/parent/child/", true);
    TestKeyMatch5Fn("/parent/child/?status=1&type=2", "/parent/child", false);
    TestKeyMatch5Fn("/parent/child?status=1&type=2", "/parent/child/", false);

    TestKeyMatch5Fn("/foo", "/foo", true);
    TestKeyMatch5Fn("/foo", "/foo*", true);
    TestKeyMatch5Fn("/foo", "/foo/*", false);
    TestKeyMatch5Fn("/foo/bar", "/foo", false);
    TestKeyMatch5Fn("/foo/bar", "/foo*", false);
    TestKeyMatch5Fn("/foo/bar", "/foo/*", true);
    TestKeyMatch5Fn("/foobar", "/foo", false);
    TestKeyMatch5Fn("/foobar", "/foo*", false);
    TestKeyMatch5Fn("/foobar", "/foo/*", false);

    TestKeyMatch5Fn("/", "/{resource}", false);
    TestKeyMatch5Fn("/resource1", "/{resource}", true);
    TestKeyMatch5Fn("/myid", "/{id}/using/{resId}", false);
    TestKeyMatch5Fn("/myid/using/myresid", "/{id}/using/{resId}", true);

    TestKeyMatch5Fn("/proxy/myid", "/proxy/{id}/*", false);
    TestKeyMatch5Fn("/proxy/myid/", "/proxy/{id}/*", true);
    TestKeyMatch5Fn("/proxy/myid/res", "/proxy/{id}/*", true);
    TestKeyMatch5Fn("/proxy/myid/res/res2", "/proxy/{id}/*", true);
    TestKeyMatch5Fn("/proxy/myid/res/res2/res3", "/proxy/{id}/*", true);
    TestKeyMatch5Fn("/proxy/", "/proxy/{id}/*", false);

    TestKeyMatch5Fn("/proxy/myid?status=1&type=2", "/proxy/{id}/*", false);
    TestKeyMatch5Fn("/proxy/myid/res?status=1&type=2", "/proxy/{id}/*", true);
    TestKeyMatch5Fn("/proxy/myid/res/res2?status=1&type=2", "/proxy/{id}/*", true);
    TestKeyMatch5Fn("/proxy/myid/res/res2/res3?status=1&type=2", "/proxy/{id}/*", true);
}

void TestRegexMatchFn(std::string key1, std::string key2, bool res) {
    auto evaluator = casbin::ExprtkEvaluator();
    auto func = casbin::ExprtkFunctionFactory::GetExprtkFunction(casbin::ExprtkFunctionType::RegexMatch, 2);
    evaluator.AddFunction("regexMatch", func);
    evaluator.AddIdentifier("key1", key1);
    evaluator.AddIdentifier("key2", key2);
    evaluator.Eval("regexMatch(key1, key2)");
    bool my_res = evaluator.GetBoolean();
    EXPECT_EQ(res, my_res);
}

TEST(TestBuiltInFunctions, TestRegexMatch) {
    TestRegexMatchFn("/topic/create", "/topic/create", true);
    TestRegexMatchFn("/topic/create/123", "/topic/create", false);
    TestRegexMatchFn("/topic/delete", "/topic/create", false);
    TestRegexMatchFn("/topic/edit", "/topic/edit/[0-9]+", false);
    TestRegexMatchFn("/topic/edit/123", "/topic/edit/[0-9]+", true);
    TestRegexMatchFn("/topic/edit/abc", "/topic/edit/[0-9]+", false);
    TestRegexMatchFn("/foo/delete/123", "/topic/delete/[0-9]+", false);
    TestRegexMatchFn("/topic/delete/0", "/topic/delete/[0-9]+", true);
    TestRegexMatchFn("/topic/edit/123s", "/topic/delete/[0-9]+", false);
}

void TestIPMatchFn(std::string ip1, std::string ip2, bool res) {
    auto evaluator = casbin::ExprtkEvaluator();
    auto func = casbin::ExprtkFunctionFactory::GetExprtkFunction(casbin::ExprtkFunctionType::IpMatch, 2);
    evaluator.AddFunction("ipMatch", func);
    evaluator.AddIdentifier("key1", ip1);
    evaluator.AddIdentifier("key2", ip2);
    evaluator.Eval("ipMatch(key1, key2)");
    bool my_res = evaluator.GetBoolean();
    EXPECT_EQ(res, my_res);
}

TEST(TestBuiltInFunctions, TestIPMatch) {
    TestIPMatchFn("192.168.2.123", "192.168.2.0/24", true);
    TestIPMatchFn("192.168.2.123", "192.168.3.0/24", false);
    TestIPMatchFn("192.168.2.123", "192.168.2.0/16", true);
    TestIPMatchFn("192.168.2.123", "192.168.2.123/32", true);
    TestIPMatchFn("10.0.0.11", "10.0.0.0/8", true);
    TestIPMatchFn("11.0.0.123", "10.0.0.0/8", false);
}

} // namespace
