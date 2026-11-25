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

#include <cctype>

#ifndef ADAPTER_CPP
#define ADAPTER_CPP

#include "casbin/exception/casbin_adapter_exception.h"
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
    if (key.empty())
        throw CasbinAdapterException("invalid policy rule: missing policy type");

    auto sec_it = model->m.find(key.substr(0, 1));
    if (sec_it != model->m.end()) {
        auto ast_it = sec_it->second.assertion_map.find(key);
        if (ast_it != sec_it->second.assertion_map.end() && ast_it->second) {
            ast_it->second->policy.emplace(std::vector<std::string>(tokens.begin() + 1, tokens.end()));
            return;
        }
    }

    throw CasbinAdapterException("invalid policy rule: unknown policy type " + key);
}

// PolicyLineToCsv joins a policy rule into a CSV policy line that SplitPolicyLine reads back. A field is quoted when it
// contains a comma or a double quote, or starts or ends with whitespace. Fields with a line break are rejected, because
// policy lines are loaded one physical line at a time.
std::string PolicyLineToCsv(const std::string& p_type, const std::vector<std::string>& rule) {
    std::vector<std::string> record{p_type};
    record.insert(record.end(), rule.begin(), rule.end());

    std::string line;
    for (size_t i = 0; i < record.size(); i++) {
        const std::string& field = record[i];
        if (field.find_first_of("\r\n") != std::string::npos)
            throw CasbinAdapterException("invalid policy field: line breaks are not allowed");

        if (i > 0)
            line += ", ";

        bool quote = field.find_first_of(",\"") != std::string::npos ||
                     (!field.empty() && (std::isspace(static_cast<unsigned char>(field.front())) || std::isspace(static_cast<unsigned char>(field.back()))));
        if (!quote) {
            line += field;
            continue;
        }

        line += '"';
        for (char c : field) {
            if (c == '"')
                line += '"';
            line += c;
        }
        line += '"';
    }
    return line;
}

} // namespace casbin

#endif // ADAPTER_CPP
