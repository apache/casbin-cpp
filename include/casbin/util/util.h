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

#ifndef CASBIN_CPP_UTIL_UTIL
#define CASBIN_CPP_UTIL_UTIL

#include <string>
#include <vector>

#include "built_in_functions.h"

namespace casbin {

// ArrayEquals determines whether two std::string arrays are identical.
bool ArrayEquals(std::vector<std::string> a, std::vector<std::string> b);

// ArrayRemoveDuplicates removes any duplicated elements in a std::string array.
void ArrayRemoveDuplicates(std::vector<std::string>& s);

std::string ArrayToString(const std::vector<std::string>& arr);

bool EndsWith(std::string_view base, std::string_view suffix);

/**
 * escapeAssertion escapes the dots in the assertion, because the expression evaluation doesn't support such variable names.
 *
 * @param s the value of the matcher and effect assertions.
 * @return the escaped value.
 */
std::string EscapeAssertion(std::string s);

std::vector<size_t> FindAllOccurences(std::string_view data, std::string_view toSearch);

template <typename Base, typename T>
bool IsInstanceOf(const T*);

std::vector<std::string> JoinSlice(const std::string& a, const std::vector<std::string>& slice);

std::string Join(const std::vector<std::string>& vos, const std::string& sep = " ");

// RemoveComments removes the comments starting with # in the text.
std::string RemoveComments(std::string_view s);

// SetSubtract returns the elements in `a` that aren't in `b`.
std::vector<std::string> SetSubtract(const std::vector<std::string>& a, const std::vector<std::string>& b);

std::vector<std::string> Split(std::string str, const std::string& del, int limit = 0);

std::string& LTrim(std::string& str, const std::string& chars = "\t\n\v\f\r ");

std::string& RTrim(std::string& str, const std::string& chars = "\t\n\v\f\r ");

std::string Trim(std::string& str, const std::string& chars = "\t\n\v\f\r ");

// HasEval determine whether matcher contains function eval
bool HasEval(const std::string& s);

// ReplaceEvalWithMap replace function eval with the value of its parameters via given sets.
std::string ReplaceEvalWithMap(const std::string& src, std::unordered_map<std::string, std::string>& sets);

// GetEvalValue returns the parameters of function eval
std::vector<std::string> GetEvalValue(std::string s);
} // namespace casbin

#endif