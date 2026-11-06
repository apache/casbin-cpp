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

void bindPyCachedEnforcer(py::module &m) {
    py::class_<casbin::CachedEnforcer, casbin::Enforcer>(m, "CachedEnforcer")
        .def(py::init<>(), "Enforcer is the default constructor.")
        .def(py::init<const std::string &, const std::string &>(), R"doc(
            Enforcer initializes an enforcer with a model file and a policy file.
            @param model_path the path of the model file.
            @param policy_file the path of the policy file.
        )doc")
        .def(py::init<const std::string &, std::shared_ptr<casbin::Adapter>>(), R"doc(
            Enforcer initializes an enforcer with a database adapter.
            @param model_path the path of the model file.
            @param adapter the adapter.
        )doc")
        .def(py::init<std::shared_ptr<casbin::Model>, std::shared_ptr<casbin::Adapter>>(), R"doc(
            Enforcer initializes an enforcer with a model and a database adapter.
            @param m the model.
            @param adapter the adapter.
        )doc")
        .def(py::init<std::shared_ptr<casbin::Model>>(), R"doc(
            Enforcer initializes an enforcer with a model.
            @param m the model.
        )doc")
        .def(py::init<const std::string &>(), R"doc(
            Enforcer initializes an enforcer with a model file.
            @param model_path the path of the model file.
        )doc")
        .def(py::init<const std::string &, const std::string &, bool>(), R"doc(
            Enforcer initializes an enforcer with a model file, a policy file and an enable log flag.
            @param model_path the path of the model file.
            @param policy_file the path of the policy file.
            @param enable_log whether to enable Casbin's log.
        )doc")

        .def("InvalidateCache", &casbin::CachedEnforcer::InvalidateCache)

        .def("Enforce", py::overload_cast<const casbin::DataVector&>(&casbin::CachedEnforcer::Enforce), R"doc(
            Enforce with a map param,decides whether a "subject" can access a "object"
            with the operation "action", input parameters are usually: (sub, obj, act).
        )doc")
        .def("Enforce", py::overload_cast<const casbin::DataList &>(&casbin::CachedEnforcer::Enforce), R"doc(
            Enforce with a map param,decides whether a "subject" can access a "object"
            with the operation "action", input parameters are usually: (sub, obj, act).
        )doc")
        .def("Enforce", py::overload_cast<const casbin::DataMap &>(&casbin::CachedEnforcer::Enforce), R"doc(
            Enforce with a map param,decides whether a "subject" can access a "object"
            with the operation "action", input parameters are usually: (sub, obj, act).
        )doc")

        .def("EnforceWithMatcher", py::overload_cast<const std::string &, const casbin::DataList &>(&casbin::CachedEnforcer::EnforceWithMatcher), R"doc(
            EnforceWithMatcher use a custom matcher to decides whether a "subject" can
            access a "object" with the operation "action", input parameters are
            usually: (matcher, sub, obj, act), use model matcher by default when
            matcher is "".
        )doc")
        .def("EnforceWithMatcher", py::overload_cast<const std::string &, const casbin::DataMap &>(&casbin::CachedEnforcer::EnforceWithMatcher), R"doc(
            EnforceWithMatcher use a custom matcher to decides whether a "subject" can
            access a "object" with the operation "action", input parameters are
            usually: (matcher, sub, obj, act), use model matcher by default when
            matcher is "".
        )doc");
}
