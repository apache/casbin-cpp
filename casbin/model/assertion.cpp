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

#ifndef ASSERTION_CPP
#define ASSERTION_CPP

#include <algorithm>

#include "casbin/exception/illegal_argument_exception.h"
#include "casbin/model/assertion.h"

namespace casbin {

void Assertion::BuildIncrementalRoleLinks(std::shared_ptr<RoleManager>& rm, policy_op op, const PoliciesValues& rules) {
    this->rm = rm;
    size_t char_count = count(this->value.begin(), this->value.end(), '_');

    if (char_count < 2)
        throw IllegalArgumentException("the number of \"_\" in role definition should be at least 2");

    for (std::vector<std::string> rule : rules) {
        if (rule.size() < char_count)
            throw IllegalArgumentException("grouping policy elements do not meet role definition");

        if (rule.size() > char_count)
            rule = std::vector<std::string>(rule.begin(), rule.begin() + char_count);

        std::vector<std::string> domain(rule.begin() + 2, rule.end());

        switch (op) {
            case policy_op::policy_add:
                this->rm->AddLink(rule[0], rule[1], domain);
                break;
            case policy_op::policy_remove:
                this->rm->DeleteLink(rule[0], rule[1], domain);
        }
    }
}

void Assertion::BuildRoleLinks(std::shared_ptr<RoleManager>& rm) {
    this->rm = rm;
    size_t char_count = count(this->value.begin(), this->value.end(), '_');

    if (char_count < 2)
        throw IllegalArgumentException("the number of \"_\" in role definition should be at least 2");

    for (std::vector<std::string> rule : policy) {
        if (rule.size() < char_count)
            throw IllegalArgumentException("grouping policy elements do not meet role definition");
        if (rule.size() > char_count)
            rule = std::vector<std::string>(rule.begin(), rule.begin() + char_count);

        std::vector<std::string> domain(rule.begin() + 2, rule.end());
        this->rm->AddLink(rule[0], rule[1], domain);
    }

    // DefaultLogger df_logger;
    // df_logger.EnableLog(true);

    // Logger *logger = &df_logger;
    // LogUtil::SetLogger(*logger);

    // LogUtil::LogPrint("Role links for: " + Key);

    // this->rm->PrintRoles();
}

} // namespace casbin

#endif // ASSERTION_CPP
