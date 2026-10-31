/*
 * Copyright 2020 The casbin Authors. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CASBIN_CPP_UTIL_BUILT_IN_FUNCTIONS
#define CASBIN_CPP_UTIL_BUILT_IN_FUNCTIONS

namespace casbin {

// KeyMatch determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
// For example, "/foo/bar" matches "/foo/*"
bool KeyMatch(const std::string& key1, const std::string& key2);

// KeyGet returns the matched part
// For example, "/foo/bar/foo" matches "/foo/*"
// "bar/foo" will been returned
std::string KeyGet(const std::string& key1, const std::string& key2);

// KeyMatch2 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
// For example, "/foo/bar" matches "/foo/*", "/resource1" matches "/:resource"
bool KeyMatch2(const std::string& key1, const std::string& key2);

// KeyGet2 returns value matched pattern
// For example, "/resource1" matches "/:resource"
// if the path_var == "resource", then "resource1" will be returned
std::string KeyGet2(const std::string& key1, const std::string& key2, const std::string& path_var);

// KeyMatch3 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
// For example, "/foo/bar" matches "/foo/*", "/resource1" matches "/{resource}"
bool KeyMatch3(const std::string& key1, const std::string& key2);

// KeyGet3 returns value matched pattern
// For example, "project/proj_project1_admin/" matches "project/proj_{project}_admin/"
// if the pathVar == "project", then "project1" will be returned
std::string KeyGet3(const std::string& key1, const std::string& key2, const std::string& path_var);

// KeyMatch4 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
// Besides what KeyMatch3 does, KeyMatch4 can also match repeated patterns:
// "/parent/123/child/123" matches "/parent/{id}/child/{id}"
// "/parent/123/child/456" does not match "/parent/{id}/child/{id}"
// But KeyMatch3 will match both.
bool KeyMatch4(const std::string& key1, const std::string& key2);

// KeyMatch5 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
// The query string in key1 is ignored.
// For example, "/foo/bar?status=1&type=2" matches "/foo/bar", "/parent/child1" matches "/parent/*" and "/parent/{id}"
bool KeyMatch5(const std::string& key1, const std::string& key2);

// RegexMatch determines whether key1 matches the pattern of key2 in regular expression.
bool RegexMatch(const std::string& key1, const std::string& key2);

// IPMatch determines whether IP address ip1 matches the pattern of IP address ip2, ip2 can be an IP address or a CIDR pattern.
// For example, "192.168.2.123" matches "192.168.2.0/24"
bool IPMatch(const std::string& ip1, const std::string& ip2);

} // namespace casbin

#endif