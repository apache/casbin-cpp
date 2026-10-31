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

#include <cctype>

#ifndef ADAPTER_CPP
#define ADAPTER_CPP

#include "casbin/persist/adapter.h"
#include "casbin/util/util.h"

namespace casbin {

// SplitPolicyLine splits a CSV policy line into fields. Unquoted fields are trimmed, a field wrapped in double quotes
// may contain commas and keeps its inner whitespace, and "" inside it stands for one double quote.
std::vector<std::string> SplitPolicyLine(const std::string& line) {
    std::vector<std::string> tokens;
    std::string token;
    bool in_quotes = false;
    bool quoted = false;
    for (size_t i = 0; i < line.size(); i++) {
        char c = line[i];
        if (in_quotes) {
            if (c != '"')
                token += c;
            else if (i + 1 < line.size() && line[i + 1] == '"')
                token += line[++i];
            else
                in_quotes = false;
        } else if (c == ',') {
            tokens.push_back(quoted ? token : Trim(token));
            token.clear();
            quoted = false;
        } else if (c == '"' && !quoted && Trim(token).empty()) {
            in_quotes = quoted = true;
        } else if (!quoted || !std::isspace(static_cast<unsigned char>(c))) {
            token += c;
        }
    }
    tokens.push_back(quoted ? token : Trim(token));
    return tokens;
}

// LoadPolicyLine loads a text line as a policy rule to model.
void LoadPolicyLine(const std::string& line, const std::shared_ptr<Model>& model) {
    if (line.empty() || line.find('#') == 0)
        return;

    std::vector<std::string> tokens = SplitPolicyLine(line);

    std::string key = tokens[0];
    std::string sec = key.substr(0, 1);
    std::vector<std::string> new_tokens(tokens.begin() + 1, tokens.end());

    if (model->m.find(sec) == model->m.end())
        model->m[sec] = AssertionMap();

    model->m[sec].assertion_map[key]->policy.emplace(new_tokens);
}

} // namespace casbin

#endif // ADAPTER_CPP
