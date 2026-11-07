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

#ifndef ENFORCER_CACHED_CPP
#define ENFORCER_CACHED_CPP

#include "casbin/effect/default_effector.h"
#include "casbin/enforcer_cached.h"
#include "casbin/exception/casbin_adapter_exception.h"
#include "casbin/exception/casbin_enforcer_exception.h"
#include "casbin/persist/file_adapter/file_adapter.h"
#include "casbin/persist/watcher_ex.h"
#include "casbin/rbac/default_role_manager.h"
#include "casbin/util/util.h"

namespace casbin {

/**
 * Enforcer is the default constructor.
 */
CachedEnforcer ::CachedEnforcer() {
    this->enableCache = true;
}

/**
 * Enforcer initializes an enforcer with a model file and a policy file.
 *
 * @param model_path the path of the model file.
 * @param policyFile the path of the policy file.
 */
CachedEnforcer ::CachedEnforcer(const std::string& model_path, const std::string& policy_file)
    : Enforcer(model_path, policy_file) {
    this->enableCache = true;
}

/**
 * Enforcer initializes an enforcer with a database adapter.
 *
 * @param model_path the path of the model file.
 * @param adapter the adapter.
 */
CachedEnforcer ::CachedEnforcer(const std::string& model_path, std::shared_ptr<Adapter> adapter)
    : Enforcer(model_path, adapter) {
    this->enableCache = true;
}

/**
 * Enforcer initializes an enforcer with a model and a database adapter.
 *
 * @param m the model.
 * @param adapter the adapter.
 */
CachedEnforcer ::CachedEnforcer(const std::shared_ptr<Model>& m, std::shared_ptr<Adapter> adapter)
    : Enforcer(m, adapter) {
    this->enableCache = true;
}

/**
 * Enforcer initializes an enforcer with a model.
 *
 * @param m the model.
 */
CachedEnforcer ::CachedEnforcer(const std::shared_ptr<Model>& m)
    : Enforcer(m) {
    this->enableCache = true;
}

/**
 * Enforcer initializes an enforcer with a model file.
 *
 * @param model_path the path of the model file.
 */
CachedEnforcer ::CachedEnforcer(const std::string& model_path)
    : Enforcer(model_path) {
    this->enableCache = true;
}

/**
 * Enforcer initializes an enforcer with a model file, a policy file and an enable log flag.
 *
 * @param model_path the path of the model file.
 * @param policyFile the path of the policy file.
 * @param enableLog whether to enable Casbin's log.
 */
CachedEnforcer ::CachedEnforcer(const std::string& model_path, const std::string& policy_file, bool enable_log)
    : Enforcer(model_path, policy_file, enable_log) {
    this->enableCache = true;
}

CachedEnforcer::CachedEnforcer(const CachedEnforcer& ce)
    : Enforcer(ce) {
    this->m = ce.m;
    this->enableCache = ce.enableCache;
}

CachedEnforcer::CachedEnforcer(CachedEnforcer&& ce) noexcept
    : Enforcer(ce) {
    this->m = std::move(ce.m);
    this->enableCache = ce.enableCache;
}

void CachedEnforcer::EnableCache(const bool& shouldEnableCache) {
    this->enableCache = shouldEnableCache;
}

std::pair<bool, bool> CachedEnforcer::getCachedResult(const std::string& key) {
    locker.lock();
    bool ok = m.count(key);
    if (!ok) {
        locker.unlock();
        return std::pair<bool, bool>(false, false);
    }

    std::pair<bool, bool> res_ok(m[key], ok);
    locker.unlock();
    return res_ok;
}

void CachedEnforcer::setCachedResult(const std::string& key, const bool& res) {
    locker.lock();
    m[key] = res;
    locker.unlock();
}

void CachedEnforcer::InvalidateCache() {
    m.clear();
}

// Enforce decides whether a "subject" can access a "object" with the operation
// "action", input parameters are usually: (sub, obj, act).
bool CachedEnforcer ::Enforce(std::shared_ptr<IEvaluator> evalator) {
    return EnforceWithMatcher("", evalator);
}

bool CachedEnforcer::Enforce(const DataVector& params) {
    return EnforceWithMatcher("", params);
}

// Enforce with a vector param,decides whether a "subject" can access a "object"
// with the operation "action", input parameters are usually: (sub, obj, act).
bool CachedEnforcer::Enforce(const DataList& params) {
    return EnforceWithMatcher("", params);
}

// Enforce with a map param,decides whether a "subject" can access a "object"
// with the operation "action", input parameters are usually: (sub, obj, act).
bool CachedEnforcer::Enforce(const DataMap& params) {
    return EnforceWithMatcher("", params);
}

// EnforceWithMatcher use a custom matcher to decides whether a "subject" can
// access a "object" with the operation "action", input parameters are usually:
// (matcher, sub, obj, act), use model matcher by default when matcher is "".
bool CachedEnforcer ::EnforceWithMatcher(const std::string& matcher, std::shared_ptr<IEvaluator> evalator) {
    return Enforcer::EnforceWithMatcher(matcher, evalator);
}

// EnforceWithMatcher use a custom matcher to decides whether a "subject" can
// access a "object" with the operation "action", input parameters are usually:
// (matcher, sub, obj, act), use model matcher by default when matcher is "".
bool CachedEnforcer::EnforceWithMatcher(const std::string& matcher, const DataVector& params) {
    if (!enableCache) {
        return Enforcer::EnforceWithMatcher(matcher, params);
    }

    std::string key;
    for (const auto& r : params) {
        if (const auto string_param = std::get_if<std::string>(&r))
            key += *string_param;
        key += "$$";
    }
    key += matcher;
    key += "$";

    std::pair<bool, bool> res_ok = getCachedResult(key);

    if (res_ok.second) {
        return res_ok.first;
    }

    bool res = Enforcer::EnforceWithMatcher(matcher, params);
    setCachedResult(key, res);
    return res;
}

// EnforceWithMatcher use a custom matcher to decides whether a "subject" can
// access a "object" with the operation "action", input parameters are usually:
// (matcher, sub, obj, act), use model matcher by default when matcher is "".
bool CachedEnforcer::EnforceWithMatcher(const std::string& matcher, const DataList& params) {
    if (!enableCache) {
        return Enforcer::EnforceWithMatcher(matcher, params);
    }

    std::string key;
    for (const auto& r : params) {
        if (const auto string_param = std::get_if<std::string>(&r))
            key += *string_param;
        key += "$$";
    }
    key += matcher;
    key += "$";

    std::pair<bool, bool> res_ok = getCachedResult(key);

    if (res_ok.second) {
        return res_ok.first;
    }

    bool res = Enforcer::EnforceWithMatcher(matcher, params);
    setCachedResult(key, res);
    return res;
}

// EnforceWithMatcher use a custom matcher to decides whether a "subject" can
// access a "object" with the operation "action", input parameters are usually:
// (matcher, sub, obj, act), use model matcher by default when matcher is "".
bool CachedEnforcer::EnforceWithMatcher(const std::string& matcher, const DataMap& params) {
    if (!enableCache) {
        return Enforcer::EnforceWithMatcher(matcher, params);
    }

    std::string key;
    for (auto [param_name, param_value] : params) {
        if (const auto string_value = std::get_if<std::string>(&param_value))
            key += *string_value;
        key += "$$";
    }
    key += matcher;
    key += "$";

    std::pair<bool, bool> res_ok = getCachedResult(key);

    if (res_ok.second) {
        return res_ok.first;
    }

    bool res = Enforcer::EnforceWithMatcher(matcher, params);
    setCachedResult(key, res);
    return res;
}

} // namespace casbin

#endif // ENFORCER_CACHED_CPP
