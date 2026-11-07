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

#ifndef JOIN_CPP
#define JOIN_CPP

#include "casbin/util/util.h"

namespace casbin {

std::string Join(const std::vector<std::string>& vos, const std::string& sep) {
    std::string fs = vos[0];
    for (size_t i = 1; i < vos.size(); i++)
        fs += sep + vos[i];
    return fs;
}

} // namespace casbin

#endif // JOIN_CPP
