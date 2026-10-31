/*
 * Copyright 2020 The casbin Authors. All Rights Reserved.
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
 */

#include "casbin/pch.h"

#ifndef ESCAPE_ASSERTION_CPP
#define ESCAPE_ASSERTION_CPP

#include <regex>

#include "casbin/util/util.h"

namespace casbin {

/**
 * escapeAssertion escapes the dots in the assertion, because the expression evaluation doesn't support such variable names.
 *
 * @param s the value of the matcher and effect assertions.
 * @return the escaped value.
 */
std::string EscapeAssertion(std::string s) {
    static const std::regex regex_s("([()\\s|&,=!><+\\-*/]|^)([rp][0-9]*)\\.");

    std::string res;
    size_t start = 0;
    while (start < s.size()) {
        size_t quote = s.find_first_of("\"'", start);
        res += std::regex_replace(s.substr(start, quote - start), regex_s, "$1$2_");
        if (quote == std::string::npos)
            break;

        size_t end = s.find(s[quote], quote + 1);
        if (end == std::string::npos)
            end = s.size() - 1;
        res += s.substr(quote, end - quote + 1);
        start = end + 1;
    }

    return res;
}

} // namespace casbin

#endif // ESCAPE_ASSERTION_CPP
