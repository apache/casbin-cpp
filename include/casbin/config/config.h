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

#ifndef CASBIN_CPP_CONFIG_CONFIG
#define CASBIN_CPP_CONFIG_CONFIG

#include <memory>
#include <mutex>
#include <unordered_map>

#include "./config_interface.h"

namespace casbin {

class Config : public ConfigInterface {
private:
    static const std::string DEFAULT_SECTION;
    static const std::string DEFAULT_COMMENT;
    static const std::string DEFAULT_COMMENT_SEM;
    static std::mutex mtx_lock;

    std::unordered_map<std::string, std::unordered_map<std::string, std::string>> data;

    /**
     * addConfig adds a new section->key:value to the configuration.
     */
    bool AddConfig(std::string section, const std::string& option, const std::string& value);

    void Parse(const std::string& f_name);

    void ParseBuffer(std::istream* buf);

public:
    /**
     * NewConfig create an empty configuration representation from file.
     *
     * @param confName the path of the model file.
     * @return the constructor of Config.
     */
    static std::shared_ptr<Config> NewConfig(const std::string& conf_name);

    /**
     * newConfigFromText create an empty configuration representation from text.
     *
     * @param text the model text.
     * @return the constructor of Config.
     */
    static std::shared_ptr<Config> NewConfigFromText(const std::string& text);

    bool GetBool(std::string_view key);

    Config();

    Config(const std::string& conf_name);

    int GetInt(std::string_view key);

    float GetFloat(std::string_view key);

    std::string GetString(std::string_view key);

    std::vector<std::string> GetStrings(std::string_view key);

    void Set(std::string_view key, const std::string& value);

    std::string Get(std::string_view key);
};

} // namespace casbin

#endif