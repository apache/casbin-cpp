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

#ifndef JOIN_SLICE_CPP
#define JOIN_SLICE_CPP

#include "casbin/util/util.h"

namespace casbin {

std::vector<std::string> JoinSlice(const std::string& a, const std::vector<std::string>& slice) {
    std::vector<std::string> result(slice.size() + 1);
    size_t i = 0;
    result[i] = a;
    for (const std::string& it : slice)
        result[++i] = it;
    return result;
}

} // namespace casbin

#endif // JOIN_SLICE_CPP
