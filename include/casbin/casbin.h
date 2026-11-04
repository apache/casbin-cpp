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

#ifndef CASBIN_CPP_CASBIN_H
#define CASBIN_CPP_CASBIN_H

#include "casbin_types.h"
#include "enforcer.h"
#include "enforcer_cached.h"
#include "enforcer_interface.h"
#include "enforcer_synced.h"
#include "pch.h"
// persist
#include "persist/adapter.h"
#include "persist/batch_adapter.h"
#include "persist/default_watcher.h"
#include "persist/default_watcher_ex.h"
#include "persist/filtered_adapter.h"
#include "persist/persist.h"
#include "persist/watcher.h"
#include "persist/watcher_ex.h"

// persist/file_adapter
#include "persist/file_adapter/batch_file_adapter.h"
#include "persist/file_adapter/file_adapter.h"
#include "persist/file_adapter/filtered_file_adapter.h"
#include "persist/watcher_update.h"

// effect
#include "effect/default_effector.h"
#include "effect/effect.h"
#include "effect/effector.h"

// ip_parser
// ip_parser/exception
#include "ip_parser/exception/parser_exception.h"
// ip_parser/parser
#include "ip_parser/parser/CIDR.h"
#include "ip_parser/parser/CIDRMask.h"
#include "ip_parser/parser/IP.h"
#include "ip_parser/parser/IPMask.h"
#include "ip_parser/parser/IPNet.h"
#include "ip_parser/parser/IPv4.h"
#include "ip_parser/parser/Print.h"
#include "ip_parser/parser/allFF.h"
#include "ip_parser/parser/byte.h"
#include "ip_parser/parser/dtoi.h"
#include "ip_parser/parser/equal.h"
#include "ip_parser/parser/parseCIDR.h"
#include "ip_parser/parser/parseIP.h"
#include "ip_parser/parser/parseIPv4.h"
#include "ip_parser/parser/parseIPv6.h"
#include "ip_parser/parser/xtoi.h"

// exception
#include "exception/casbin_adapter_exception.h"
#include "exception/casbin_enforcer_exception.h"
#include "exception/casbin_rbac_exception.h"
#include "exception/exception.h"
#include "exception/illegal_argument_exception.h"
#include "exception/io_exception.h"
#include "exception/missing_required_sections.h"
#include "exception/unsupported_operation_exception.h"

// config
#include "config/config.h"
#include "config/config_interface.h"

// model
#include "model/assertion.h"
#include "model/evaluator.h"
#include "model/function.h"
#include "model/model.h"

// util
#include "util/built_in_functions.h"
#include "util/ticker.h"
#include "util/util.h"

// error
#include "error/error.h"

// exprtk
#include "exprtk/exprtk.hpp"

// rbac
#include "rbac/default_role_manager.h"
#include "rbac/rbac.h"
#include "rbac/role_manager.h"

// log
#include "log/Logger.h"
#include "log/default_logger.h"
#include "log/log_util.h"

#endif // CASBIN_CPP_CASBIN_H
