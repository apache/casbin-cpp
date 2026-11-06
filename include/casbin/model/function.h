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

#ifndef CASBIN_CPP_MODEL_FUNCTION
#define CASBIN_CPP_MODEL_FUNCTION

#include <list>

#include "../util/built_in_functions.h"
#include "evaluator.h"

namespace casbin {

class FunctionMap {
public:
    std::shared_ptr<IEvaluator> evalator;

    FunctionMap();

    bool Evaluate(const std::string& expression);

    void ProcessFunctions(const std::string& expression);

    // LoadFunctionMap loads an initial function map.
    void LoadFunctionMap();
};

}; // namespace casbin

#endif