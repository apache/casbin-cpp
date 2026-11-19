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

/* This is the main file for python bindings workflow */

#include <pybind11/pybind11.h>
#include "py_casbin.h"

namespace py = pybind11;

PYBIND11_MODULE(pycasbin, m) {
    m.doc() = R"pbdoc(
        Casbin Authorization Library
        -----------------------

        .. currentmodule:: pycasbin

        .. autosummary::
           :toctree: _generate

           Enforcer
    )pbdoc";
    
    bindPyEnforcer(m);
    bindPyCachedEnforcer(m);
    bindPyModel(m);
    bindPyConfig(m);
    bindPySyncedEnforcer(m);
    bindPyAdapter(m);

    m.attr("__version__") = PY_CASBIN_VERSION;
}
