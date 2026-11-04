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

#ifndef ENDS_WITH_CPP
#define ENDS_WITH_CPP

#include "casbin/util/util.h"

namespace casbin {

bool EndsWith(std::string_view base, std::string_view suffix) {
    size_t base_len = base.length();
    size_t suffix_len = suffix.length();
    return base.substr(base_len - suffix_len, suffix_len).compare(suffix) == 0;
}

} // namespace casbin

#endif // ENDS_WITH_CPP
