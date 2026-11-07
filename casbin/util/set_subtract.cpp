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

#ifndef SET_SUBSTRACT_CPP
#define SET_SUBSTRACT_CPP

#include <unordered_map>

#include "casbin/util/util.h"

namespace casbin {

// SetSubtract returns the elements in `a` that aren't in `b`.
std::vector<std::string> SetSubtract(const std::vector<std::string>& a, const std::vector<std::string>& b) {
    std::unordered_map<std::string, bool> mb;
    mb.reserve(b.size());

    for (const std::string& it : b)
        mb[it] = true;

    std::vector<std::string> diff;
    diff.reserve(a.size());

    for (const std::string& it : a)
        if (!mb[it])
            diff.push_back(it);

    return diff;
}

} // namespace casbin

#endif // SET_SUBSTRACT_CPP
