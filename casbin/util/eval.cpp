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

#include "casbin/pch.h"

#ifndef EVAL_CPP
#define EVAL_CPP

#include <regex>

#include "casbin/util/util.h"

namespace casbin {

std::regex evalReg("\\beval\\(([^)]*)\\)",
                   std::regex_constants::icase);

// HasEval determine whether matcher contains function eval
bool HasEval(const std::string& s) {
    return std::regex_search(s, evalReg);
}

// ReplaceEvalWithMap replace function eval with the value of its parameters via given sets.
std::string ReplaceEvalWithMap(const std::string& src, std::unordered_map<std::string, std::string>& sets) {
    std::string replacedExp = "";
    std::string srcCpy = src;
    std::smatch m;

    while (std::regex_search(srcCpy, m, evalReg)) {
        if (m.empty()) {
            return src;
        }
        std::string key = m[1];
        bool found = sets.find(key) != sets.end();

        replacedExp += m.prefix();
        if (!found) {
            replacedExp += m[0];
        } else {
            replacedExp += sets[key];
        }
        srcCpy = m.suffix();
    }

    replacedExp += srcCpy;

    return replacedExp;
}

// GetEvalValue returns the parameters of function eval
std::vector<std::string> GetEvalValue(std::string s) {
    std::vector<std::string> rules;
    rules.reserve(10);
    std::smatch m;

    while (std::regex_search(s, m, evalReg)) {
        if (m.empty()) {
            return rules;
        }
        std::string rule = m[1];

        rules.push_back(rule);
        s = m.suffix();
    }

    return rules;
}

} // namespace casbin

#endif // EVAL_CPP
