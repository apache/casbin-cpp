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

void bindPyEnforcer(py::module& m) {
    py::class_<casbin::Enforcer>(m, "Enforcer")
        .def(py::init<>(), "")
        .def(py::init<const std::string &, const std::string &>(), "")
        .def(py::init<const std::string &, std::shared_ptr<casbin::Adapter>>(), "")
        .def(py::init<std::shared_ptr<casbin::Model>, std::shared_ptr<casbin::Adapter>>(), "")
        .def(py::init<std::shared_ptr<casbin::Model>>(), "")
        .def(py::init<const std::string &>(), "")
        .def(py::init<const std::string &, const std::string &, bool>(), "")

        .def("InitWithFile", &casbin::Enforcer::InitWithFile, "InitWithFile initializes an enforcer with a model file and a policy file.")
        .def("InitWithAdapter", &casbin::Enforcer::InitWithAdapter, "InitWithAdapter initializes an enforcer with a database adapter.")
        .def("InitWithModelAndAdapter", &casbin::Enforcer::InitWithModelAndAdapter, "InitWithModelAndAdapter initializes an enforcer with a model and a database adapter.")
        .def("Initialize", &casbin::Enforcer::Initialize)
        .def("LoadModel", &casbin::Enforcer::LoadModel, R"doc(
            LoadModel reloads the model from the model CONF file.
            Because the policy is attached to a model, so the policy is invalidated and 
            needs to be reloaded by calling LoadPolicy().
        )doc")

        .def("GetModel", &casbin::Enforcer::GetModel, "GetModel gets the current model.")
        .def("SetModel", &casbin::Enforcer::SetModel, "SetModel sets the current model.")
        .def("GetAdapter", &casbin::Enforcer::GetAdapter, "GetAdapter gets the current adapter.")
        .def("SetAdapter", &casbin::Enforcer::SetAdapter, "SetAdapter sets the current adapter.")
        .def("SetWatcher", &casbin::Enforcer::SetWatcher, "SetWatcher sets the current watcher.")
        .def("GetRoleManager", &casbin::Enforcer::GetRoleManager, "GetRoleManager gets the current role manager.")
        .def("SetRoleManager", &casbin::Enforcer::SetRoleManager, "SetRoleManager sets the current role manager.")
        .def("SetEffector", &casbin::Enforcer::SetEffector, "SetEffector sets the current effector.")
        .def("ClearPolicy", &casbin::Enforcer::ClearPolicy, "ClearPolicy clears all policy.")
        .def("LoadPolicy", &casbin::Enforcer::LoadPolicy, "LoadPolicy reloads the policy from file/database.")
        // .def("LoadFilteredPolicy", &casbin::Enforcer::LoadFilteredPolicy, "LoadFilteredPolicy reloads a filtered policy from file/database.")
        .def("IsFiltered", &casbin::Enforcer::IsFiltered, "IsFiltered returns true if the loaded policy has been filtered.")
        .def("SavePolicy", &casbin::Enforcer::SavePolicy, "SavePolicy saves the current policy (usually after changed with Casbin API) back to file/database.")
        .def("EnableEnforce", &casbin::Enforcer::EnableEnforce, "EnableEnforce changes the enforcing state of Casbin, when Casbin is disabled, all access will be allowed by the Enforce() function.")
        .def("EnableLog", &casbin::Enforcer::EnableLog, "EnableLog changes whether Casbin will log messages to the Logger.")
        .def("EnableAutoNotifyWatcher", &casbin::Enforcer::EnableAutoNotifyWatcher, "EnableAutoNotifyWatcher controls whether to save a policy rule automatically notify the Watcher when it is added or removed.")
        .def("EnableAutoSave", &casbin::Enforcer::EnableAutoSave, "EnableAutoSave controls whether to save a policy rule automatically to the adapter when it is added or removed.")
        .def("EnableAutoBuildRoleLinks", &casbin::Enforcer::EnableAutoBuildRoleLinks, "EnableAutoBuildRoleLinks controls whether to rebuild the role inheritance relations when a role is added or deleted.")
        .def("BuildRoleLinks", &casbin::Enforcer::BuildRoleLinks, "BuildRoleLinks manually rebuild the role inheritance relations.")
        .def("BuildIncrementalRoleLinks", &casbin::Enforcer::BuildIncrementalRoleLinks, "BuildIncrementalRoleLinks provides incremental build the role inheritance relations.")
        .def("Enforce", py::overload_cast<const casbin::DataVector &>(&casbin::Enforcer::Enforce), "Enforce with a vector param, decides whether a \"subject\" can access a \"object\" with the operation \"action\", input parameters are usually: (sub, obj, act).")
        .def("Enforce", py::overload_cast<const casbin::DataMap &>(&casbin::Enforcer::Enforce), "Enforce with a map param, decides whether a \"subject\" can access a \"object\" with the operation \"action\", input parameters are usually: (sub, obj, act).")
        .def("EnforceWithMatcher", py::overload_cast<const std::string &, const casbin::DataList &>(&casbin::Enforcer::EnforceWithMatcher), "EnforceWithMatcher use a custom matcher to decides whether a \"subject\" can access a \"object\" with the operation \"action\", input parameters are usually: (matcher, sub, obj, act), use model matcher by default when matcher is \"\".")
        .def("EnforceWithMatcher", py::overload_cast<const std::string &, const casbin::DataMap &>(&casbin::Enforcer::EnforceWithMatcher), "EnforceWithMatcher use a custom matcher to decides whether a \"subject\" can access a \"object\" with the operation \"action\", input parameters are usually: (matcher, sub, obj, act), use model matcher by default when matcher is \"\".")
        .def("BatchEnforce", &casbin::Enforcer::BatchEnforce, "BatchEnforce enforce in batches")
        .def("BatchEnforceWithMatcher", &casbin::Enforcer::BatchEnforceWithMatcher, "BatchEnforceWithMatcher enforce with matcher in batches")

        /* Management API member functions. */

        .def("GetAllSubjects", &casbin::Enforcer::GetAllSubjects)
        .def("GetAllNamedSubjects", &casbin::Enforcer::GetAllNamedSubjects)
        .def("GetAllObjects", &casbin::Enforcer::GetAllObjects)
        .def("GetAllNamedObjects", &casbin::Enforcer::GetAllNamedObjects)
        .def("GetAllActions", &casbin::Enforcer::GetAllActions)
        .def("GetAllNamedActions", &casbin::Enforcer::GetAllNamedActions)
        .def("GetAllRoles", &casbin::Enforcer::GetAllRoles)
        .def("GetAllNamedRoles", &casbin::Enforcer::GetAllNamedRoles)
        .def("GetPolicy", &casbin::Enforcer::GetPolicy)
        .def("GetFilteredPolicy", &casbin::Enforcer::GetFilteredPolicy)
        .def("GetNamedPolicy", &casbin::Enforcer::GetNamedPolicy)
        .def("GetFilteredNamedPolicy", &casbin::Enforcer::GetFilteredNamedPolicy)
        .def("GetGroupingPolicy", &casbin::Enforcer::GetGroupingPolicy)
        .def("GetFilteredGroupingPolicy", &casbin::Enforcer::GetFilteredGroupingPolicy)
        .def("GetNamedGroupingPolicy", &casbin::Enforcer::GetNamedGroupingPolicy)
        .def("GetFilteredNamedGroupingPolicy", &casbin::Enforcer::GetFilteredNamedGroupingPolicy)

        .def("HasPolicy", &casbin::Enforcer::HasPolicy)
        .def("HasNamedPolicy", &casbin::Enforcer::HasNamedPolicy)
        .def("AddPolicy", &casbin::Enforcer::AddPolicy)
        .def("AddNamedPolicy", &casbin::Enforcer::AddNamedPolicy)
        .def("AddNamedPolicies", &casbin::Enforcer::AddNamedPolicies)
        .def("RemovePolicy", &casbin::Enforcer::RemovePolicy)
        .def("RemovePolicies", &casbin::Enforcer::RemovePolicies)
        .def("RemoveFilteredPolicy", &casbin::Enforcer::RemoveFilteredPolicy)
        .def("RemoveNamedPolicies", &casbin::Enforcer::RemoveNamedPolicies)
        .def("RemoveFilteredNamedPolicy", &casbin::Enforcer::RemoveFilteredNamedPolicy)
        .def("HasNamedGroupingPolicy", &casbin::Enforcer::HasNamedGroupingPolicy)
        .def("AddGroupingPolicy", &casbin::Enforcer::AddGroupingPolicy)
        .def("AddGroupingPolicies", &casbin::Enforcer::AddGroupingPolicies)
        .def("AddNamedGroupingPolicy", &casbin::Enforcer::AddNamedGroupingPolicy)
        .def("AddNamedGroupingPolicies", &casbin::Enforcer::AddNamedGroupingPolicies)
        .def("RemoveGroupingPolicy", &casbin::Enforcer::RemoveGroupingPolicy)
        .def("RemoveGroupingPolicies", &casbin::Enforcer::RemoveGroupingPolicies)
        .def("RemoveFilteredGroupingPolicy", &casbin::Enforcer::RemoveFilteredGroupingPolicy)
        .def("RemoveNamedGroupingPolicy", &casbin::Enforcer::RemoveNamedGroupingPolicy)
        .def("RemoveNamedGroupingPolicies", &casbin::Enforcer::RemoveNamedGroupingPolicies)
        .def("RemoveFilteredNamedGroupingPolicy", &casbin::Enforcer::RemoveFilteredNamedGroupingPolicy)
        // .def("AddFunction", &casbin::Enforcer::AddFunction)
        .def("UpdateGroupingPolicy", &casbin::Enforcer::UpdateGroupingPolicy)
        .def("UpdateNamedGroupingPolicy", &casbin::Enforcer::UpdateNamedGroupingPolicy)
        .def("UpdatePolicy", &casbin::Enforcer::UpdatePolicy)
        .def("UpdateNamedPolicy", &casbin::Enforcer::UpdateNamedPolicy)
        .def("UpdatePolicies", &casbin::Enforcer::UpdatePolicies)
        .def("UpdateNamedPolicies", &casbin::Enforcer::UpdateNamedPolicies)

        /* RBAC API member functions. */

        .def("GetRolesForUser", &casbin::Enforcer::GetRolesForUser)
        .def("GetUsersForRole", &casbin::Enforcer::GetUsersForRole)
        .def("HasRoleForUser", &casbin::Enforcer::HasRoleForUser)
        .def("AddRoleForUser", &casbin::Enforcer::AddRoleForUser)
        .def("AddRolesForUser", &casbin::Enforcer::AddRolesForUser)
        .def("AddPermissionForUser", &casbin::Enforcer::AddPermissionForUser)
        .def("DeletePermissionForUser", &casbin::Enforcer::DeletePermissionForUser)
        .def("DeletePermissionsForUser", &casbin::Enforcer::DeletePermissionsForUser)
        .def("GetPermissionsForUser", &casbin::Enforcer::GetPermissionsForUser)
        .def("HasPermissionForUser", &casbin::Enforcer::HasPermissionForUser)
        .def("GetImplicitRolesForUser", &casbin::Enforcer::GetImplicitRolesForUser)
        .def("GetImplicitPermissionsForUser", &casbin::Enforcer::GetImplicitPermissionsForUser)
        .def("GetImplicitUsersForPermission", &casbin::Enforcer::GetImplicitUsersForPermission)
        .def("DeleteRoleForUser", &casbin::Enforcer::DeleteRoleForUser)
        .def("DeleteRolesForUser", &casbin::Enforcer::DeleteRolesForUser)
        .def("DeleteUser", &casbin::Enforcer::DeleteUser)
        .def("DeleteRole", &casbin::Enforcer::DeleteRole)
        .def("DeletePermission", &casbin::Enforcer::DeletePermission)

        /* Internal API member functions omitted */

        /* RBAC API with domains.*/

        .def("GetUsersForRoleInDomain", &casbin::Enforcer::GetUsersForRoleInDomain)
        .def("GetRolesForUserInDomain", &casbin::Enforcer::GetRolesForUserInDomain)
        .def("GetPermissionsForUserInDomain", &casbin::Enforcer::GetPermissionsForUserInDomain)
        .def("AddRoleForUserInDomain", &casbin::Enforcer::AddRoleForUserInDomain)
        .def("DeleteRoleForUserInDomain", &casbin::Enforcer::DeleteRoleForUserInDomain);
}