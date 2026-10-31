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
 * This is a test file for testing the Utility methods in casbin
 */

#include <casbin/casbin.h>
#include <gtest/gtest.h>

namespace {

void TestEscapeAssertionFn(const std::string& s, const std::string& res) {
    std::string my_res = casbin::EscapeAssertion(s);
    ASSERT_EQ(my_res, res);
}

TEST(TestUtil, TestEscapeAssertion) {
    TestEscapeAssertionFn("r.attr.value == p.attr", "r_attr.value == p_attr");
    TestEscapeAssertionFn("r.attp.value || p.attr", "r_attp.value || p_attr");
    TestEscapeAssertionFn("r.attp.value &&p.attr", "r_attp.value &&p_attr");
    TestEscapeAssertionFn("r.attp.value >p.attr", "r_attp.value >p_attr");
    TestEscapeAssertionFn("r.attp.value <p.attr", "r_attp.value <p_attr");
    TestEscapeAssertionFn("r.attp.value +p.attr", "r_attp.value +p_attr");
    TestEscapeAssertionFn("r.attp.value -p.attr", "r_attp.value -p_attr");
    TestEscapeAssertionFn("r.attp.value *p.attr", "r_attp.value *p_attr");
    TestEscapeAssertionFn("r.attp.value /p.attr", "r_attp.value /p_attr");
    TestEscapeAssertionFn("!r.attp.value /p.attr", "!r_attp.value /p_attr");
    TestEscapeAssertionFn("g(r.sub, p.sub) == p.attr", "g(r_sub, p_sub) == p_attr");
    TestEscapeAssertionFn("g(r.sub,p.sub) == p.attr", "g(r_sub,p_sub) == p_attr");
    TestEscapeAssertionFn("(r.attp.value || p.attr)p.u", "(r_attp.value || p_attr)p_u");
    TestEscapeAssertionFn("r.sub == \"r.my_resource\"", "r_sub == \"r.my_resource\"");
    TestEscapeAssertionFn("p.obj == 'p.resource'", "p_obj == 'p.resource'");
    TestEscapeAssertionFn("p.sub == p.obj && p.obj == \"r.something\"", "p_sub == p_obj && p_obj == \"r.something\"");
    TestEscapeAssertionFn("r.sub == \"hello p.world\" && r2.obj == p2.obj", "r_sub == \"hello p.world\" && r2_obj == p2_obj");
    TestEscapeAssertionFn("r.sub == \"a.p.p.l.e\"", "r_sub == \"a.p.p.l.e\"");
}

void TestRemoveCommentsFn(const std::string& s, const std::string& res) {
    std::string my_res = casbin::RemoveComments(s);
    ASSERT_EQ(my_res, res);
}

TEST(TestUtil, TestRemoveComments) {
    TestRemoveCommentsFn("r.act == p.act # comments", "r.act == p.act");
    TestRemoveCommentsFn("r.act == p.act#comments", "r.act == p.act");
    TestRemoveCommentsFn("r.act == p.act###", "r.act == p.act");
    TestRemoveCommentsFn("### comments", "");
    TestRemoveCommentsFn("r.act == p.act", "r.act == p.act");
}

void TestArrayEqualsFn(const std::vector<std::string>& a, const std::vector<std::string>& b, bool res) {
    bool my_res = casbin::ArrayEquals(a, b);
    ASSERT_EQ(my_res, res);
}

TEST(TestUtil, TestArrayEquals) {
    TestArrayEqualsFn({"a", "b", "c"}, {"a", "b", "c"}, true);
    TestArrayEqualsFn({"a", "b", "c"}, {"a", "b"}, false);
    TestArrayEqualsFn({"a", "b", "c"}, {"a", "c", "b"}, true);
    TestArrayEqualsFn({"a", "b", "c"}, {}, false);
}

void testContainEval(std::string s, bool res) { ASSERT_EQ(casbin::HasEval(s), res); }

TEST(TestUtil, TestContainEval) {
    testContainEval("eval() && a && b && c", true);
    testContainEval("eval) && a && b && c", false);
    testContainEval("eval)( && a && b && c", false);
    testContainEval("eval(c * (a + b)) && a && b && c", true);
    testContainEval("xeval() && a && b && c", false);
}

void testReplaceEvalWithMap(std::string s, std::unordered_map<std::string, std::string> sets, std::string res) { ASSERT_EQ(casbin::ReplaceEvalWithMap(s, sets), res); }

TEST(TestUtil, TestReplaceEvalWithMap) {
    testReplaceEvalWithMap("eval(rule1)", {{"rule1", "a == b"}}, "a == b");
    testReplaceEvalWithMap("eval(rule1) && c && d", {{"rule1", "a == b"}}, "a == b && c && d");
    testReplaceEvalWithMap("eval(rule1)", {{}}, "eval(rule1)");
    testReplaceEvalWithMap("eval(rule1) && c && d", {{}}, "eval(rule1) && c && d");
    testReplaceEvalWithMap("eval(rule1) || eval(rule2)", {{"rule1", "a == b"}, {"rule2", "a == c"}}, "a == b || a == c");
    testReplaceEvalWithMap("eval(rule1) || eval(rule2) && c && d", {{"rule1", "a == b"}, {"rule2", "a == c"}}, "a == b || a == c && c && d");
    testReplaceEvalWithMap("eval(rule1) || eval(rule2)", {{"rule1", "a == b"}}, "a == b || eval(rule2)");
    testReplaceEvalWithMap("eval(rule1) || eval(rule2) && c && d", {{"rule1", "a == b"}}, "a == b || eval(rule2) && c && d");
    testReplaceEvalWithMap("eval(rule1) || eval(rule2)", {{"rule2", "a == b"}}, "eval(rule1) || a == b");
    testReplaceEvalWithMap("eval(rule1) || eval(rule2) && c && d", {{"rule2", "a == b"}}, "eval(rule1) || a == b && c && d");
    testReplaceEvalWithMap("eval(rule1) || eval(rule2)", {}, "eval(rule1) || eval(rule2)");
    testReplaceEvalWithMap("eval(rule1) || eval(rule2) && c && d", {}, "eval(rule1) || eval(rule2) && c && d");
}

void testGetEvalValue(std::string s, std::vector<std::string> res) {
    auto myRes = casbin::GetEvalValue(s);

    ASSERT_EQ(res.size(), myRes.size());

    for (size_t i = 0; i < res.size(); i++) {
        ASSERT_EQ(res[i], myRes[i]);
    }
}

TEST(TestUtil, TestGetEvalValue) {
    testGetEvalValue("eval(a) && a && b && c", {"a"});
    testGetEvalValue("a && eval(a) && b && c", {"a"});
    testGetEvalValue("eval(a) && eval(b) && a && b && c", {"a", "b"});
    testGetEvalValue("a && eval(a) && eval(b) && b && c", {"a", "b"});
}

} // namespace
