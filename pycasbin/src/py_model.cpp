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

void PyLoadModelFromConfig(casbin::Model* model, std::shared_ptr<casbin::Config> config) {
    model->LoadModelFromConfig(config);
}

void bindPyModel(py::module &m) {
    py::class_<casbin::Model, std::shared_ptr<casbin::Model>>(m, "Model")
        .def(py::init<>())
        .def(py::init<const std::string &>())

        .def_readonly_static("required_sections", &casbin::Model::required_sections)

        .def("HasSection", &casbin::Model::HasSection)
        .def("AddDef", &casbin::Model::AddDef, "AddDef adds an assertion to the model.")
        .def("LoadModel", &casbin::Model::LoadModel, "LoadModel loads the model from model CONF file.")
        .def("LoadModelFromText", &casbin::Model::LoadModelFromText, "LoadModelFromText loads the model from the text.")
        .def("LoadModelFromConfig", &casbin::Model::LoadModelFromConfig)
        .def("PrintModel", &casbin::Model::PrintModel, "PrintModel prints the model to the log.")

        .def("BuildIncrementalRoleLinks", &casbin::Model::BuildIncrementalRoleLinks)
        .def("BuildRoleLinks", &casbin::Model::BuildRoleLinks, "BuildRoleLinks initializes the roles in RBAC.")
        .def("PrintPolicy", &casbin::Model::PrintPolicy, "PrintPolicy prints the policy to log.")
        .def("ClearPolicy", &casbin::Model::ClearPolicy, "ClearPolicy clears all current policy.")
        .def("GetPolicy", &casbin::Model::GetPolicy, "GetPolicy gets all rules in a policy.")
        .def("GetFilteredPolicy", &casbin::Model::GetFilteredPolicy, "GetFilteredPolicy gets rules based on field filters from a policy.")
        .def("HasPolicy", &casbin::Model::HasPolicy, "HasPolicy determines whether a model has the specified policy rule.")
        .def("AddPolicy", &casbin::Model::AddPolicy, "AddPolicy adds a policy rule to the model.")
        .def("AddPolicies", &casbin::Model::AddPolicies, "AddPolicies adds policy rules to the model.")
        .def("UpdatePolicy", &casbin::Model::UpdatePolicy, "UpdatePolicy updates a policy rule from the model.")
        .def("UpdatePolicies", &casbin::Model::UpdatePolicies, "UpdatePolicies updates a set of policy rules from the model.")
        .def("RemovePolicy", &casbin::Model::RemovePolicy, "RemovePolicy removes a policy rule from the model.")
        .def("RemovePolicies", &casbin::Model::RemovePolicies, "RemovePolicies removes policy rules from the model.")
        .def("RemoveFilteredPolicy", &casbin::Model::RemoveFilteredPolicy, "RemoveFilteredPolicy removes policy rules based on field filters from the model.")
        .def("GetValuesForFieldInPolicy", &casbin::Model::GetValuesForFieldInPolicy, "GetValuesForFieldInPolicy gets all values for a field for all rules in a policy, duplicated values are removed.")
        .def("GetValuesForFieldInPolicyAllTypes", &casbin::Model::GetValuesForFieldInPolicyAllTypes, "GetValuesForFieldInPolicyAllTypes gets all values for a field for all rules in a policy of all p_types, duplicated values are removed.")

        .def_static("NewModel", &casbin::Model::NewModel, "NewModel creates an empty model.")
        .def_static("NewModelFromFile", &casbin::Model::NewModelFromFile, "NewModelFromFile creates a model from a .CONF file.")
        .def_static("NewModelFromString", &casbin::Model::NewModelFromString, "NewModel creates a model from a std::string which contains model text.");
}
