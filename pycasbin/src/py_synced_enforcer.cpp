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
#include <pybind11/chrono.h>
#include <casbin/casbin.h>

#include "py_casbin.h"

namespace py = pybind11;

void bindPySyncedEnforcer(py::module& m) {
    py::class_<casbin::SyncedEnforcer, casbin::Enforcer>(m, "SyncedEnforcer")
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

        .def("StartAutoLoadPolicy", &casbin::SyncedEnforcer::StartAutoLoadPolicy, "StartAutoLoadPolicy starts a thread that will go through every specified duration call LoadPolicy")
        .def("IsAutoLoadingRunning", &casbin::SyncedEnforcer::IsAutoLoadingRunning, "IsAutoLoadingRunning check if SyncedEnforcer is auto loading policies")
        .def("StopAutoLoadPolicy", &casbin::SyncedEnforcer::StopAutoLoadPolicy, "StopAutoLoadPolicy causes the thread to exit")
        .def("SetWatcher", &casbin::SyncedEnforcer::SetWatcher, "SetWatcher sets the current watcher.")
        .def("LoadModel", &casbin::SyncedEnforcer::LoadModel, "LoadModel reloads the model from the model CONF file.")
        .def("ClearPolicy", &casbin::SyncedEnforcer::ClearPolicy, "ClearPolicy clears all policy.")
        .def("LoadPolicy", &casbin::SyncedEnforcer::LoadPolicy, "LoadPolicy reloads the policy from file/database.")
        // .def("LoadFilteredPolicy", &casbin::SyncedEnforcer::LoadFilteredPolicy, "LoadFilteredPolicy reloads a filtered policy from file/database.")
        .def("SavePolicy", &casbin::SyncedEnforcer::SavePolicy, "SavePolicy saves the current policy (usually after changed with Casbin API) back to file/database.")
        .def("BuildRoleLinks", &casbin::SyncedEnforcer::BuildRoleLinks, "BuildRoleLinks manually rebuild the role inheritance relations.")
        .def("Enforce", py::overload_cast<const casbin::DataVector &>(&casbin::SyncedEnforcer::Enforce), "Enforce with a vector param, decides whether a \"subject\" can access a \"object\" with the operation \"action\", input parameters are usually: (sub, obj, act).")
        .def("Enforce", py::overload_cast<const casbin::DataMap &>(&casbin::SyncedEnforcer::Enforce), "Enforce with a map param, decides whether a \"subject\" can access a \"object\" with the operation \"action\", input parameters are usually: (sub, obj, act).")
        .def("BatchEnforce", &casbin::SyncedEnforcer::BatchEnforce, "BatchEnforce enforce in batches")
        .def("BatchEnforceWithMatcher", &casbin::SyncedEnforcer::BatchEnforceWithMatcher, "BatchEnforceWithMatcher enforce with matcher in batches")

        /* Management API member functions. */

        .def("GetAllSubjects", &casbin::SyncedEnforcer::GetAllSubjects)
        .def("GetAllNamedSubjects", &casbin::SyncedEnforcer::GetAllNamedSubjects)
        .def("GetAllObjects", &casbin::SyncedEnforcer::GetAllObjects)
        .def("GetAllNamedObjects", &casbin::SyncedEnforcer::GetAllNamedObjects)
        .def("GetAllNamedActions", &casbin::SyncedEnforcer::GetAllNamedActions)
        .def("GetAllRoles", &casbin::SyncedEnforcer::GetAllRoles)
        .def("GetAllNamedRoles", &casbin::SyncedEnforcer::GetAllNamedRoles)
        .def("GetPolicy", &casbin::SyncedEnforcer::GetPolicy)
        .def("GetNamedPolicy", &casbin::SyncedEnforcer::GetNamedPolicy)
        .def("GetFilteredNamedPolicy", &casbin::SyncedEnforcer::GetFilteredNamedPolicy)
        .def("GetGroupingPolicy", &casbin::SyncedEnforcer::GetGroupingPolicy)
        .def("GetFilteredGroupingPolicy", &casbin::SyncedEnforcer::GetFilteredGroupingPolicy)
        .def("GetNamedGroupingPolicy", &casbin::SyncedEnforcer::GetNamedGroupingPolicy)
        .def("GetFilteredNamedGroupingPolicy", &casbin::SyncedEnforcer::GetFilteredNamedGroupingPolicy)

        .def("HasPolicy", &casbin::SyncedEnforcer::HasPolicy)
        .def("HasNamedPolicy", &casbin::SyncedEnforcer::HasNamedPolicy)
        .def("AddPolicy", &casbin::SyncedEnforcer::AddPolicy)
        .def("AddNamedPolicy", &casbin::SyncedEnforcer::AddNamedPolicy)
        .def("AddNamedPolicies", &casbin::SyncedEnforcer::AddNamedPolicies)
        .def("RemovePolicy", &casbin::SyncedEnforcer::RemovePolicy)
        .def("RemovePolicies", &casbin::SyncedEnforcer::RemovePolicies)
        .def("RemoveFilteredPolicy", &casbin::SyncedEnforcer::RemoveFilteredPolicy)
        .def("RemoveNamedPolicies", &casbin::SyncedEnforcer::RemoveNamedPolicies)
        .def("RemoveFilteredNamedPolicy", &casbin::SyncedEnforcer::RemoveFilteredNamedPolicy)
        .def("HasNamedGroupingPolicy", &casbin::SyncedEnforcer::HasNamedGroupingPolicy)
        .def("AddGroupingPolicy", &casbin::SyncedEnforcer::AddGroupingPolicy)
        .def("AddGroupingPolicies", &casbin::SyncedEnforcer::AddGroupingPolicies)
        .def("AddNamedGroupingPolicy", &casbin::SyncedEnforcer::AddNamedGroupingPolicy)
        .def("AddNamedGroupingPolicies", &casbin::SyncedEnforcer::AddNamedGroupingPolicies)
        .def("RemoveGroupingPolicy", &casbin::SyncedEnforcer::RemoveGroupingPolicy)
        .def("RemoveGroupingPolicies", &casbin::SyncedEnforcer::RemoveGroupingPolicies)
        .def("RemoveFilteredGroupingPolicy", &casbin::SyncedEnforcer::RemoveFilteredGroupingPolicy)
        .def("RemoveNamedGroupingPolicy", &casbin::SyncedEnforcer::RemoveNamedGroupingPolicy)
        .def("RemoveNamedGroupingPolicies", &casbin::SyncedEnforcer::RemoveNamedGroupingPolicies)
        .def("RemoveFilteredNamedGroupingPolicy", &casbin::SyncedEnforcer::RemoveFilteredNamedGroupingPolicy)
        // .def("AddFunction", &casbin::SyncedEnforcer::AddFunction)
        .def("UpdateGroupingPolicy", &casbin::SyncedEnforcer::UpdateGroupingPolicy)
        .def("UpdateNamedGroupingPolicy", &casbin::SyncedEnforcer::UpdateNamedGroupingPolicy)
        .def("UpdatePolicy", &casbin::SyncedEnforcer::UpdatePolicy)
        .def("UpdateNamedPolicy", &casbin::SyncedEnforcer::UpdateNamedPolicy)
        .def("UpdatePolicies", &casbin::SyncedEnforcer::UpdatePolicies)
        .def("UpdateNamedPolicies", &casbin::SyncedEnforcer::UpdateNamedPolicies);
}
