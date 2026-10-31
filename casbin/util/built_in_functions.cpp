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

#include "casbin/pch.h"

#ifndef BUILT_IN_FUNCTIONS_CPP
#define BUILT_IN_FUNCTIONS_CPP

#include <map>
#include <regex>
#include <unordered_map>

#include "casbin/exception/illegal_argument_exception.h"
#include "casbin/ip_parser/parser/CIDR.h"
#include "casbin/ip_parser/parser/IP.h"
#include "casbin/ip_parser/parser/parseCIDR.h"
#include "casbin/ip_parser/parser/parseIP.h"
#include "casbin/model/function.h"
#include "casbin/rbac/role_manager.h"
#include "casbin/util/built_in_functions.h"
#include "casbin/util/util.h"

namespace casbin {

namespace {
    static const std::regex capturingColonNonSlashRegex("(.*?):[^/]+(.*?)");
    static const std::regex enclosedPlaceHolderRegex("(.*?)\\{[^/]+?\\}(.*?)");

    std::string ReplacePattern(std::string const& in, std::string const& pattern, std::string const& replacement) {
        std::string result = in;
        std::size_t pos = 0;
        // Replace all occurrences of pattern with replacement
        while ((pos = result.find(pattern, pos)) != std::string::npos) {
            result.replace(pos, pattern.length(), replacement);
            pos += replacement.length(); // Move over change
        }
        return result;
    }

    std::string PrepareWildCardMatching(const std::string& value) {
        return ReplacePattern(value, "/*", "/.*");
    }

    std::string EscapeCurlyBraces(const std::string& value) {
        std::string intermediate = ReplacePattern(value, "{", "\\{");
        return ReplacePattern(intermediate, "}", "\\}");
    }

    static const char regexSpecialChars[] = "\\^$.|?*+()[]{}";
    static const char regexSpecialCharsAndColon[] = "\\^$.|?*+()[]{}:";

    // MatchWithoutRegex matches key1 against key2 without a regex when key2 is a plain path, optionally ending with "/*".
    // It returns false when key2 contains other special characters, then the caller has to fall back to the regex.
    bool MatchWithoutRegex(const std::string& key1, const std::string& key2, const char* special_chars, bool& res) {
        std::size_t pos = key2.find_first_of(special_chars);
        if (pos == std::string::npos) {
            res = key1 == key2;
            return true;
        }

        if (pos > 0 && pos + 1 == key2.size() && key2[pos] == '*' && key2[pos - 1] == '/') {
            // Same as "/.*" in the regex: same prefix, and "." does not match line terminators.
            res = key1.compare(0, pos, key2, 0, pos) == 0 && key1.find_first_of("\r\n", pos) == std::string::npos;
            return true;
        }

        return false;
    }

    // GetRegex returns the compiled regex of pattern, each thread compiles a pattern only once.
    const std::regex& GetRegex(const std::string& pattern) {
        thread_local std::unordered_map<std::string, std::regex> cache;
        auto it = cache.find(pattern);
        if (it != cache.end())
            return it->second;

        if (cache.size() >= 1024)
            cache.clear();

        return cache.emplace(pattern, std::regex(pattern)).first->second;
    }
}

// KeyMatch determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
// For example, "/foo/bar" matches "/foo/*"
bool KeyMatch(const std::string& key1, const std::string& key2) {
    size_t pos = key2.find("*");

    if (pos == std::string ::npos)
        return key1 == key2;

    if (key1.length() > pos)
        return key1.substr(0, pos) == key2.substr(0, pos);

    return key1 == key2.substr(0, pos);
}

// KeyGet returns the matched part
// For example, "/foo/bar/foo" matches "/foo/*"
// "bar/foo" will been returned
std::string KeyGet(const std::string& key1, const std::string& key2) {
    size_t pos = key2.find("*");

    if (pos == std::string ::npos)
        return "";

    if (key1.length() > pos)
        if (key1.substr(0, pos) == key2.substr(0, pos))
            return key1.substr(pos, key1.length() - pos);

    return "";
}

// KeyMatch2 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
// For example, "/foo/bar" matches "/foo/*", "/resource1" matches "/:resource"
bool KeyMatch2(const std::string& key1, const std::string& key2) {
    bool res;
    if (MatchWithoutRegex(key1, key2, regexSpecialCharsAndColon, res))
        return res;

    std::string k2 = PrepareWildCardMatching(key2);
    k2 = std::regex_replace(k2, capturingColonNonSlashRegex, "$1[^/]+$2");
    k2 = EscapeCurlyBraces(k2);

    if (!k2.compare("*"))
        k2 = "(.*)";

    return RegexMatch(key1, "^" + k2 + "$");
}

// KeyGet2 returns value matched pattern
// For example, "/resource1" matches "/:resource"
// if the path_var == "resource", then "resource1" will be returned
std::string KeyGet2(const std::string& key1, const std::string& key2, const std::string& path_var) {
    static const std::regex colonAnyButSlashPattern(":[^/]+");    
    std::string k2 = PrepareWildCardMatching(key2);

    std::vector<std::string> keys;
    for (std::sregex_iterator it(k2.begin(), k2.end(), colonAnyButSlashPattern), end_it; it != end_it; ++it) {
        keys.push_back(it->str());
    }

    k2 = std::regex_replace(k2, capturingColonNonSlashRegex, "$1([^/]+)$2");
    k2 = EscapeCurlyBraces(k2);
    if (!k2.compare("*"))
        k2 = "(.*)";
    k2 = "^" + k2 + "$";

    std::smatch values;
    std::regex_match(key1.begin(), key1.end(), values, GetRegex(k2));

    for (int i = 0; i < keys.size(); i++)
        if (!path_var.compare(keys.at(i).substr(1)))
            return values[i + 1];

    return "";
}

// KeyMatch3 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
// For example, "/foo/bar" matches "/foo/*", "/resource1" matches "/{resource}"
bool KeyMatch3(const std::string& key1, const std::string& key2) {
    bool res;
    if (MatchWithoutRegex(key1, key2, regexSpecialChars, res))
        return res;

    std::string k2 = PrepareWildCardMatching(key2);
    k2 = std::regex_replace(k2, enclosedPlaceHolderRegex, "$1[^/]+$2");
    k2 = EscapeCurlyBraces(k2);

    return RegexMatch(key1, "^" + k2 + "$");
}

// KeyGet3 returns value matched pattern
// For example, "project/proj_project1_admin/" matches "project/proj_{project}_admin/"
// if the pathVar == "project", then "project1" will be returned
std::string KeyGet3(const std::string& key1, const std::string& key2, const std::string& path_var) {
    static const std::regex placeHolderPattern("\\{[^/]+?\\}");
    std::string k2 = PrepareWildCardMatching(key2);

    std::vector<std::string> keys;
    for (std::sregex_iterator it(k2.begin(), k2.end(), placeHolderPattern), end_it; it != end_it; ++it) {
        keys.push_back(it->str());
    }

    k2 = std::regex_replace(k2, enclosedPlaceHolderRegex, "$1([^/]+?)$2");
    k2 = EscapeCurlyBraces(k2);
    if (!k2.compare("*"))
        k2 = "(.*)";
    k2 = "^" + k2 + "$";

    std::smatch values;
    std::regex_match(key1.begin(), key1.end(), values, GetRegex(k2));

    for (int i = 0; i < keys.size(); i++)
        if (!path_var.compare(keys.at(i).substr(1, keys.at(i).length() - 2)))
            return values[i + 1];

    return "";
}

// KeyMatch4 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
// Besides what KeyMatch3 does, KeyMatch4 can also match repeated patterns:
// "/parent/123/child/123" matches "/parent/{id}/child/{id}"
// "/parent/123/child/456" does not match "/parent/{id}/child/{id}"
// But KeyMatch3 will match both.
bool KeyMatch4(const std::string& key1, const std::string& key2) {
    bool res;
    if (MatchWithoutRegex(key1, key2, regexSpecialChars, res))
        return res;

    std::string k2 = PrepareWildCardMatching(key2);

    std::vector<std::string> tokens;
    static std::regex tokens_regex("\\{([^/]+)\\}");
    for (std::sregex_iterator it(k2.begin(), k2.end(), tokens_regex), end_it; it != end_it; ++it)
        tokens.push_back(it->str());

    k2 = std::regex_replace(k2, enclosedPlaceHolderRegex, "$1([^/]+)$2");
    k2 = EscapeCurlyBraces(k2);
    k2 = "^" + k2 + "$";
    std::smatch matches;
    std::regex_match(key1.begin(), key1.end(), matches, GetRegex(k2));
    if (matches.empty())
        return false;
    if (tokens.size() != matches.size() - 1)
        throw "KeyMatch4: number of tokens is not equal to number of values";

    std::map<std::string, std::string> tokens_matches;

    for (int i = 0; i < tokens.size(); i++) {
        if (tokens_matches.find(tokens[i]) == tokens_matches.end()) {
            tokens_matches.insert(std::pair<std::string, std::string>(tokens[i], matches[i + 1]));
            continue;
        } else if (tokens_matches.at(tokens[i]).compare(matches[i + 1])) {
            return false;
        }
    }
    return true;
}

// KeyMatch5 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
// The query string in key1 is ignored.
// For example, "/foo/bar?status=1&type=2" matches "/foo/bar", "/parent/child1" matches "/parent/*" and "/parent/{id}"
bool KeyMatch5(const std::string& key1, const std::string& key2) {
    return KeyMatch3(key1.substr(0, key1.find('?')), key2);
}

// RegexMatch determines whether key1 matches the pattern of key2 in regular expression.
bool RegexMatch(const std::string& key1, const std::string& key2) {
    return std::regex_match(key1, GetRegex(key2));
}

// IPMatch determines whether IP address ip1 matches the pattern of IP address ip2, ip2 can be an IP address or a CIDR pattern.
// For example, "192.168.2.123" matches "192.168.2.0/24"
bool IPMatch(const std::string& ip1, const std::string& ip2) {
    IP objIP1 = parseIP(ip1);
    if (objIP1.isLegal == false)
        throw IllegalArgumentException("invalid argument: ip1 in IPMatch() function is not an IP address.");

    CIDR objCIDR = parseCIDR(ip2);
    if (objCIDR.ip.isLegal == false) {
        IP objIP2 = parseIP(ip2);
        if (objIP2.isLegal == false)
            throw IllegalArgumentException("invalid argument: ip1 in IPMatch() function is not an IP address.");

        return objIP1.Equal(objIP2);
    }

    return objCIDR.net.contains(objIP1);
}

} // namespace casbin

#endif // BUILT_IN_FUNCTIONS_CPP
