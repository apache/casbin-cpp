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

#ifndef CASBIN_CPP_ENFORCER_CACHED
#define CASBIN_CPP_ENFORCER_CACHED

#include <mutex>

#include "casbin/enforcer.h"

namespace casbin {

class CachedEnforcer : public Enforcer {
public:
    std::unordered_map<std::string, bool> m;
    bool enableCache;
    std::mutex locker;

    CachedEnforcer(const CachedEnforcer& ce);
    CachedEnforcer(CachedEnforcer&& ce) noexcept;

    void EnableCache(const bool& shouldEnableCache);
    std::pair<bool, bool> getCachedResult(const std::string& key);
    void setCachedResult(const std::string& key, const bool& res);
    void InvalidateCache();

public:
    /**
     * Enforcer is the default constructor.
     */
    CachedEnforcer();
    /**
     * Enforcer initializes an enforcer with a model file and a policy file.
     *
     * @param model_path the path of the model file.
     * @param policy_file the path of the policy file.
     */
    CachedEnforcer(const std::string& model_path, const std::string& policy_file);
    /**
     * Enforcer initializes an enforcer with a database adapter.
     *
     * @param model_path the path of the model file.
     * @param adapter the adapter.
     */
    CachedEnforcer(const std::string& model_path, std::shared_ptr<Adapter> adapter);
    /**
     * Enforcer initializes an enforcer with a model and a database adapter.
     *
     * @param m the model.
     * @param adapter the adapter.
     */
    CachedEnforcer(const std::shared_ptr<Model>& m, std::shared_ptr<Adapter> adapter);
    /**
     * Enforcer initializes an enforcer with a model.
     *
     * @param m the model.
     */
    CachedEnforcer(const std::shared_ptr<Model>& m);
    /**
     * Enforcer initializes an enforcer with a model file.
     *
     * @param model_path the path of the model file.
     */
    CachedEnforcer(const std::string& model_path);
    /**
     * Enforcer initializes an enforcer with a model file, a policy file and an enable log flag.
     *
     * @param model_path the path of the model file.
     * @param policy_file the path of the policy file.
     * @param enable_log whether to enable Casbin's log.
     */
    CachedEnforcer(const std::string& model_path, const std::string& policy_file, bool enable_log);

    virtual ~CachedEnforcer() = default;

    bool Enforce(std::shared_ptr<IEvaluator> evalator);

    // Enforce with a vector param,decides whether a "subject" can access a
    // "object" with the operation "action", input parameters are usually: (sub,
    // obj, act).
    bool Enforce(const DataVector& params);

    // Enforce with a vector param,decides whether a "subject" can access a
    // "object" with the operation "action", input parameters are usually: (sub,
    // obj, act).
    bool Enforce(const DataList& params);

    // Enforce with a map param,decides whether a "subject" can access a "object"
    // with the operation "action", input parameters are usually: (sub, obj, act).
    bool Enforce(const DataMap& params);

    // EnforceWithMatcher use a custom matcher to decides whether a "subject" can
    // access a "object" with the operation "action", input parameters are
    // usually: (matcher, sub, obj, act), use model matcher by default when
    // matcher is "".
    bool EnforceWithMatcher(const std::string& matcher, std::shared_ptr<IEvaluator> evalator);

    // EnforceWithMatcher use a custom matcher to decides whether a "subject" can
    // access a "object" with the operation "action", input parameters are
    // usually: (matcher, sub, obj, act), use model matcher by default when
    // matcher is "".
    bool EnforceWithMatcher(const std::string& matcher, const DataVector& params);

    // EnforceWithMatcher use a custom matcher to decides whether a "subject" can
    // access a "object" with the operation "action", input parameters are
    // usually: (matcher, sub, obj, act), use model matcher by default when
    // matcher is "".
    bool EnforceWithMatcher(const std::string& matcher, const DataList& params);

    // EnforceWithMatcher use a custom matcher to decides whether a "subject" can
    // access a "object" with the operation "action", input parameters are
    // usually: (matcher, sub, obj, act), use model matcher by default when
    // matcher is "".
    bool EnforceWithMatcher(const std::string& matcher, const DataMap& params);
};

} // namespace casbin

#endif