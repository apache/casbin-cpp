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

/* This file contains the path to various config resources within casbin */

#include <string>

#define STRINGIFY_IMPL(x) #x
#define STRINGIFY(x) STRINGIFY_IMPL(x)

static const std::string relative_path = STRINGIFY(CASBIN_PROJECT_DIR);

static const std::string basic_model_path = relative_path + "/examples/basic_model.conf";
static const std::string basic_policy_path = relative_path + "/examples/basic_policy.csv";
static const std::string basic_model_without_spaces_path = relative_path + "/examples/basic_model_without_spaces.conf";
static const std::string basic_without_users_model_path = relative_path + "/examples/basic_without_users_model.conf";
static const std::string basic_without_users_policy_path = relative_path + "/examples/basic_without_users_policy.csv";
static const std::string basic_without_resources_model_path = relative_path + "/examples/basic_without_resources_model.conf";
static const std::string basic_without_resources_policy_path = relative_path + "/examples/basic_without_resources_policy.csv";
static const std::string basic_with_root_model_path = relative_path + "/examples/basic_with_root_model.conf";

static const std::string rbac_with_not_deny_model_path = relative_path + "/examples/rbac_with_not_deny_model.conf";
static const std::string rbac_model_path = relative_path + "/examples/rbac_model.conf";
static const std::string rbac_policy_path = relative_path + "/examples/rbac_policy.csv";
static const std::string rbac_with_resource_roles_model_path = relative_path + "/examples/rbac_with_resource_roles_model.conf";
static const std::string rbac_with_resource_roles_policy_path = relative_path + "/examples/rbac_with_resource_roles_policy.csv";
static const std::string rbac_with_domains_model_path = relative_path + "/examples/rbac_with_domains_model.conf";
static const std::string rbac_with_domains_policy_path = relative_path + "/examples/rbac_with_domains_policy.csv";
static const std::string rbac_with_pattern_model_path = relative_path + "/examples/rbac_with_pattern_model.conf";
static const std::string rbac_with_pattern_policy_path = relative_path + "/examples/rbac_with_pattern_policy.csv";
static const std::string rbac_with_hierarchy_policy_path = relative_path + "/examples/rbac_with_hierarchy_policy.csv";
static const std::string rbac_with_hierarchy_with_domains_policy_path = relative_path + "/examples/rbac_with_hierarchy_with_domains_policy.csv";
static const std::string rbac_with_deny_model_path = relative_path + "/examples/rbac_with_deny_model.conf";
static const std::string rbac_with_deny_policy_path = relative_path + "/examples/rbac_with_deny_policy.csv";

static const std::string keymatch_model_path = relative_path + "/examples/keymatch_model.conf";
static const std::string keymatch_policy_path = relative_path + "/examples/keymatch_policy.csv";

static const std::string priority_model_path = relative_path + "/examples/priority_model.conf";
static const std::string priority_policy_path = relative_path + "/examples/priority_policy.csv";

static const std::string abac_model_path = relative_path + "/examples/abac_model.conf";
static const std::string abac_rule_model_path = relative_path + "/examples/abac_rule_model.conf";
static const std::string abac_rule_policy_path = relative_path + "/examples/abac_rule_policy.csv";
