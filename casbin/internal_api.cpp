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

#ifndef INTERNAL_API_CPP
#define INTERNAL_API_CPP

#include "casbin/enforcer.h"
#include "casbin/exception/unsupported_operation_exception.h"
#include "casbin/persist/batch_adapter.h"
#include "casbin/persist/watcher_ex.h"
#include "casbin/persist/watcher_update.h"
#include "casbin/util/util.h"

namespace casbin {

// addPolicy adds a rule to the current policy.
bool Enforcer::addPolicy(const std::string& sec, const std::string& p_type, const std::vector<std::string>& rule) {
    bool rule_added = m_model->AddPolicy(sec, p_type, rule);
    if (!rule_added)
        return rule_added;

    if (sec == "g") {
        PoliciesValues rules({rule});
        this->BuildIncrementalRoleLinks(policy_add, p_type, rules);
    }

    if (m_adapter && m_auto_save) {
        try {
            m_adapter->AddPolicy(sec, p_type, rule);
        } catch (UnsupportedOperationException e) {
        }
    }

    if (m_watcher && m_auto_notify_watcher) {
        if (IsInstanceOf<WatcherEx>(m_watcher.get())) {
            std::dynamic_pointer_cast<WatcherEx>(m_watcher)->UpdateForAddPolicy(rule);
        } else
            m_watcher->Update();
    }

    return rule_added;
}

// addPolicies adds rules to the current policy.
bool Enforcer::addPolicies(const std::string& sec, const std::string& p_type, const PoliciesValues& rules) {
    bool rules_added = m_model->AddPolicies(sec, p_type, rules);
    if (!rules_added)
        return rules_added;

    if (sec == "g")
        this->BuildIncrementalRoleLinks(policy_add, p_type, rules);

    if (m_adapter && m_auto_save) {
        try {
            std::dynamic_pointer_cast<BatchAdapter>(m_adapter)->AddPolicies(sec, p_type, rules);
        } catch (UnsupportedOperationException e) {
        }
    }

    if (m_watcher && m_auto_notify_watcher)
        m_watcher->Update();

    return rules_added;
}

// removePolicy removes a rule from the current policy.
bool Enforcer::removePolicy(const std::string& sec, const std::string& p_type, const std::vector<std::string>& rule) {
    bool rule_removed = m_model->RemovePolicy(sec, p_type, rule);
    if (!rule_removed)
        return rule_removed;

    if (sec == "g") {
        PoliciesValues rules({rule});
        this->BuildIncrementalRoleLinks(policy_add, p_type, rules);
    }

    if (m_adapter && m_auto_save) {
        try {
            m_adapter->RemovePolicy(sec, p_type, rule);
        } catch (UnsupportedOperationException e) {
        }
    }

    if (m_watcher && m_auto_notify_watcher) {
        if (IsInstanceOf<WatcherEx>(m_watcher.get())) {
            std::dynamic_pointer_cast<WatcherEx>(m_watcher)->UpdateForRemovePolicy(rule);
        } else
            m_watcher->Update();
    }

    return rule_removed;
}

// removePolicies removes rules from the current policy.
bool Enforcer::removePolicies(const std::string& sec, const std::string& p_type, const PoliciesValues& rules) {
    bool rules_removed = m_model->AddPolicies(sec, p_type, rules);
    if (!rules_removed)
        return rules_removed;

    if (sec == "g")
        this->BuildIncrementalRoleLinks(policy_add, p_type, rules);

    if (m_adapter && m_auto_save) {
        try {
            std::dynamic_pointer_cast<BatchAdapter>(m_adapter)->RemovePolicies(sec, p_type, rules);
        } catch (UnsupportedOperationException e) {
        }
    }

    if (m_watcher && m_auto_notify_watcher)
        m_watcher->Update();

    return rules_removed;
}

// removeFilteredPolicy removes rules based on field filters from the current policy.
bool Enforcer::removeFilteredPolicy(const std::string& sec, const std::string& p_type, int field_index, const std::vector<std::string>& field_values) {
    std::pair<int, PoliciesValues> p = m_model->RemoveFilteredPolicy(sec, p_type, field_index, field_values);
    bool rule_removed = p.first;
    PoliciesValues effects = p.second;

    if (!rule_removed)
        return rule_removed;

    if (sec == "g")
        this->BuildIncrementalRoleLinks(policy_remove, p_type, effects);

    if (m_adapter && m_auto_save) {
        try {
            m_adapter->RemoveFilteredPolicy(sec, p_type, field_index, field_values);
        } catch (UnsupportedOperationException e) {
        }
    }

    if (m_watcher && m_auto_notify_watcher) {
        if (IsInstanceOf<WatcherEx>(m_watcher.get())) {
            std::dynamic_pointer_cast<WatcherEx>(m_watcher)->UpdateForRemoveFilteredPolicy(field_index, field_values);
        } else
            m_watcher->Update();
    }

    return rule_removed;
}

bool Enforcer::updatePolicy(const std::string& sec, const std::string& p_type, const std::vector<std::string>& oldRule, const std::vector<std::string>& newRule) {
    bool is_rule_updated = m_model->UpdatePolicy(sec, p_type, oldRule, newRule);
    if (!is_rule_updated)
        return false;

    if (sec == "g") {
        this->BuildIncrementalRoleLinks(policy_remove, p_type, PoliciesValues({oldRule}));
        this->BuildIncrementalRoleLinks(policy_add, p_type, PoliciesValues({newRule}));
    }
    if (m_watcher && m_auto_notify_watcher) {
        if (IsInstanceOf<WatcherUpdatable>(m_watcher.get())) {
            std::dynamic_pointer_cast<WatcherUpdatable>(m_watcher)->UpdateForUpdatePolicy(oldRule, newRule);
        } else {
            m_watcher->Update();
        }
    }
    return is_rule_updated;
}

bool Enforcer::updatePolicies(const std::string& sec, const std::string& p_type, const PoliciesValues& oldRules, const PoliciesValues& newRules) {
    bool is_rules_updated = m_model->UpdatePolicies(sec, p_type, oldRules, newRules);
    if (!is_rules_updated)
        return false;

    if (sec == "g") {
        this->BuildIncrementalRoleLinks(policy_remove, p_type, oldRules);
        this->BuildIncrementalRoleLinks(policy_add, p_type, newRules);
    }

    if (m_watcher && m_auto_notify_watcher) {
        if (IsInstanceOf<WatcherUpdatable>(m_watcher.get())) {
            std::dynamic_pointer_cast<WatcherUpdatable>(m_watcher)->UpdateForUpdatePolicies(oldRules, newRules);
        } else {
            m_watcher->Update();
        }
    }

    return is_rules_updated;
}

} // namespace casbin

#endif // INTERNAL_API_CPP
