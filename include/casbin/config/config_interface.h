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

#ifndef CASBIN_CPP_CONFIG_CONFIG_INTERFACE
#define CASBIN_CPP_CONFIG_CONFIG_INTERFACE

#include <string>
#include <vector>

namespace casbin {

class ConfigInterface {
public:
    virtual std::string GetString(std::string_view key) = 0;
    virtual std::vector<std::string> GetStrings(std::string_view key) = 0;
    virtual bool GetBool(std::string_view key) = 0;
    virtual int GetInt(std::string_view key) = 0;
    virtual float GetFloat(std::string_view key) = 0;
    virtual void Set(std::string_view key, const std::string& value) = 0;
};

} // namespace casbin

#endif