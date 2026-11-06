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

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <casbin/casbin.h>

namespace py = pybind11;

void bindPyConfig(py::module &m) {
    py::class_<casbin::Config, std::shared_ptr<casbin::Config>>(m, "Config")
        .def(py::init<>())
        .def(py::init<const std::string&>())
        .def_static("NewConfig", &casbin::Config::NewConfig, R"doc(
           /**
            * NewConfig create an empty configuration representation from file.
            *
            * @param confName the path of the model file.
            * @return the constructor of Config.
            */
        )doc")
        .def_static("NewConfigFromText", &casbin::Config::NewConfigFromText, R"doc(
           /**
            * newConfigFromText create an empty configuration representation from text.
            *
            * @param text the model text.
            * @return the constructor of Config.
            */
        )doc")
        .def("GetBool", &casbin::Config::GetBool)
        .def("GetInt", &casbin::Config::GetInt)
        .def("GetFloat", &casbin::Config::GetFloat)
        .def("GetString", &casbin::Config::GetString)
        .def("GetStrings", &casbin::Config::GetStrings)
        .def("Set", &casbin::Config::Set)
        .def("Get", &casbin::Config::Get);
}
