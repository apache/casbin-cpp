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

#include "py_casbin.h"

namespace py = pybind11;

void bindPyBaseAdapter(py::module& m) {
    // Base Adapter use shared_ptr to manage
    // must expose this interface for enforcer build
    py::class_<casbin::Adapter, std::shared_ptr<casbin::Adapter>>(m, "Adapter")
        .def("LoadPolicy", &casbin::Adapter::LoadPolicy, "LoadPolicy loads all policy rules from the storage.")
        .def("SavePolicy", &casbin::Adapter::SavePolicy, "SavePolicy saves all policy rules to the storage.")
        .def("AddPolicy", &casbin::Adapter::AddPolicy, "AddPolicy adds a policy rule to the storage.")
        .def("RemovePolicy", &casbin::Adapter::RemovePolicy, "RemovePolicy removes a policy rule from the storage.")
        .def("RemoveFilteredPolicy", &casbin::Adapter::RemoveFilteredPolicy, "RemoveFilteredPolicy removes policy rules that match the filter from the storage.")
        .def("IsFiltered", &casbin::Adapter::IsFiltered, "IsFiltered returns true if the loaded policy has been filtered.");
}

void bindPyBatchAdapter(py::module &m) {
    py::class_<casbin::BatchAdapter, casbin::Adapter, std::shared_ptr<casbin::BatchAdapter>>(m, "BatchAdapter")
        .def("AddPolicies", &casbin::BatchAdapter::AddPolicies, "")
        .def("RemovePolicies", &casbin::BatchAdapter::RemovePolicies, "");
}

void bindPyFileAdapter(py::module &m) {
    // File adapter inhert base adapter and use shared_ptr to manage
    py::class_<casbin::FileAdapter, casbin::Adapter, std::shared_ptr<casbin::FileAdapter>>(m, "FileAdapter")
        .def(py::init<std::string>(), "")
        .def_static("NewFileAdapter", &casbin::FileAdapter::NewFileAdapter, "")
        .def("LoadPolicy", &casbin::FileAdapter::LoadPolicy, "LoadPolicy loads all policy rules from the storage.")
        .def("SavePolicy", &casbin::FileAdapter::SavePolicy, "SavePolicy saves all policy rules to the storage.")
        .def("AddPolicy", &casbin::FileAdapter::AddPolicy, "AddPolicy adds a policy rule to the storage.")
        .def("RemovePolicy", &casbin::FileAdapter::RemovePolicy, "RemovePolicy removes a policy rule from the storage.")
        .def("RemoveFilteredPolicy", &casbin::FileAdapter::RemoveFilteredPolicy, "RemoveFilteredPolicy removes policy rules that match the filter from the storage.")
        .def("IsFiltered", &casbin::FileAdapter::IsFiltered, "IsFiltered returns true if the loaded policy has been filtered.");
}

void bindPyBatchFileAdapter(py::module &m) {
    // Batch Adapter is virtual interface, maybe don't expose its' interface is ok.
    py::class_<casbin::BatchFileAdapter, casbin::BatchAdapter, casbin::FileAdapter, std::shared_ptr<casbin::BatchFileAdapter>>(m, "BatchFileAdapter")
        .def(py::init<std::string>(), "")
        .def_static("NewBatchFileAdapter", &casbin::BatchFileAdapter::NewBatchFileAdapter, "")
        .def("AddPolicies", &casbin::BatchFileAdapter::AddPolicies, "")
        .def("RemovePolicies", &casbin::BatchFileAdapter::RemovePolicies, "");
}

void bindPyAdapter(py::module& m) {
    bindPyBaseAdapter(m);
    bindPyBatchAdapter(m);
    bindPyFileAdapter(m);
    bindPyBatchFileAdapter(m);
}