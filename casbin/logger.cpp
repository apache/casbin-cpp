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

#ifndef LOGGER_CPP
#define LOGGER_CPP

#include "casbin/log/Logger.h"
#include "casbin/log/log_util.h"

namespace casbin {

// Print formats using the default formats for its operands and logs the message.
template <typename T, typename... Object>
void Logger::Print(T const& arg, Object const&... objects) {
    return;
}

// Printf formats according to a format specifier and logs the message.
template <typename... Object>
void Logger::Printf(std::string const& format, Object const&... objects) {
    Print(objects...);
}

DefaultLogger LogUtil::s_logger;

} // namespace casbin

#endif // LOGGER_CPP
