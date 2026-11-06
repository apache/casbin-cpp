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

#ifndef FUNCTION_CPP
#define FUNCTION_CPP

#include "casbin/model/function.h"
#include "casbin/util/util.h"

namespace casbin {

FunctionMap::FunctionMap() {
    evalator = nullptr;
}

bool FunctionMap::Evaluate(const std::string& expression) {
    evalator->ProcessFunctions(expression);
    return evalator->Eval(expression);
}

// LoadFunctionMap loads an initial function map.
void FunctionMap::LoadFunctionMap() {
    evalator->LoadFunctions();
}

} // namespace casbin

#endif // FUNCTION_CPP
