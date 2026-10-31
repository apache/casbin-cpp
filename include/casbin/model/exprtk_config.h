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

#ifndef CASBIN_CPP_MODEL_EXPRTK_CONFIG
#define CASBIN_CPP_MODEL_EXPRTK_CONFIG

#include <memory>

#include "casbin/exprtk/exprtk.hpp"
#include "casbin/rbac/default_role_manager.h"
#include "casbin/rbac/role_manager.h"
#include "casbin/util/util.h"

namespace casbin {
using numerical_type = float;

using symbol_table_t = exprtk::symbol_table<numerical_type>;
using expression_t = exprtk::expression<numerical_type>;
using parser_t = exprtk::parser<numerical_type>;
using exprtk_func_t = exprtk::igeneric_function<numerical_type>;

struct ExprtkGFunction final : public exprtk::igeneric_function<numerical_type> {
    typedef typename exprtk::igeneric_function<numerical_type>::generic_type generic_type;

    typedef typename generic_type::scalar_view scalar_t;
    typedef typename generic_type::vector_view vector_t;
    typedef typename generic_type::string_view string_t;

    typedef typename exprtk::igeneric_function<numerical_type>::parameter_list_t parameter_list_t;

private:
    std::shared_ptr<casbin::RoleManager> rm_;

public:
    ExprtkGFunction(const std::string& idenfier) : exprtk::igeneric_function<numerical_type>(idenfier), rm_(nullptr) {}

    ExprtkGFunction(const std::string& idenfier, std::shared_ptr<RoleManager> rm) : exprtk::igeneric_function<numerical_type>(idenfier), rm_(rm) {}

    bool UpdateRoleManager(std::shared_ptr<RoleManager> rm) {
        this->rm_ = rm;

        return true;
    }

    inline numerical_type operator()(parameter_list_t parameters) override {
        bool res = false;

        // check value cnt
        if (parameters.size() != 2 && parameters.size() != 3) {
            return numerical_type(res);
        }

        // check value type
        for (std::size_t i = 0; i < parameters.size(); ++i) {
            generic_type& gt = parameters[i];

            if (generic_type::e_scalar == gt.type) {
                return numerical_type(res);
            } else if (generic_type::e_vector == gt.type) {
                return numerical_type(res);
            }
        }

        std::string name1 = exprtk::to_str(string_t(parameters[0]));
        std::string name2 = exprtk::to_str(string_t(parameters[1]));
        std::string domain;
        std::vector<std::string> domains;

        if (parameters.size() == 3) {
            domain = exprtk::to_str(string_t(parameters[2]));
            domains.push_back(domain);
        }

        if (this->rm_ == nullptr)
            res = name1 == name2;
        else {
            res = rm_->HasLink(name1, name2, domains);
        }

        return numerical_type(res);
    }
};

struct ExprtkMatchFunction final : public exprtk::igeneric_function<numerical_type> {
    typedef typename exprtk::igeneric_function<numerical_type>::generic_type generic_type;

    typedef typename generic_type::scalar_view scalar_t;
    typedef typename generic_type::vector_view vector_t;
    typedef typename generic_type::string_view string_t;

    typedef typename exprtk::igeneric_function<numerical_type>::parameter_list_t parameter_list_t;

private:
    casbin::MatchingFunc func_;

public:
    ExprtkMatchFunction(const std::string& idenfier, casbin::MatchingFunc func) : exprtk::igeneric_function<numerical_type>(idenfier), func_(func) {}

    ExprtkMatchFunction() : exprtk::igeneric_function<numerical_type>("ss") {}

    inline numerical_type operator()(parameter_list_t parameters) override {
        bool res = false;

        // check value cnt
        if (parameters.size() != 2) {
            return numerical_type(res);
        }

        // check value type
        for (std::size_t i = 0; i < parameters.size(); ++i) {
            generic_type& gt = parameters[i];

            if (generic_type::e_scalar == gt.type) {
                return numerical_type(res);
            } else if (generic_type::e_vector == gt.type) {
                return numerical_type(res);
            }
        }

        std::string name1 = exprtk::to_str(string_t(parameters[0]));
        std::string name2 = exprtk::to_str(string_t(parameters[1]));

        if (this->func_ == nullptr)
            res = name1 == name2;
        else {
            res = this->func_(name1, name2);
        }

        return numerical_type(res);
    }
};

// KeyGet
struct ExprtkGetFunction final : public exprtk::igeneric_function<numerical_type> {
    typedef exprtk::igeneric_function<numerical_type> igenfunct_t;
    typedef typename igenfunct_t::generic_type generic_t;
    typedef typename igenfunct_t::parameter_list_t parameter_list_t;
    typedef typename generic_t::string_view string_t;

private:
    using MatchingFunc = std::function<std::string(const std::string&, const std::string&)>;
    MatchingFunc func_;

public:
    ExprtkGetFunction(const std::string& idenfier, MatchingFunc func) : igenfunct_t(idenfier, igenfunct_t::e_rtrn_string), func_(func) {}

    ExprtkGetFunction() : igenfunct_t("SS", igenfunct_t::e_rtrn_string) {}

    inline numerical_type operator()(std::string& result, parameter_list_t parameters) override {
        result.clear();

        // check value cnt
        if (parameters.size() != 2) {
            return numerical_type(0);
        }

        // check value type
        for (std::size_t i = 0; i < parameters.size(); ++i) {
            generic_type& gt = parameters[i];
            if (generic_type::e_string != gt.type) {
                return numerical_type(0);
            }
        }
        std::string key1 = exprtk::to_str(string_t(parameters[0]));
        std::string key2 = exprtk::to_str(string_t(parameters[1]));

        if (this->func_ != nullptr) {
            result = this->func_(key1, key2);
        }

        return numerical_type(0);
    }
};

struct ExprtkGetWithPathFunction final : public exprtk::igeneric_function<numerical_type> {
    typedef exprtk::igeneric_function<numerical_type> igenfunct_t;
    typedef typename igenfunct_t::generic_type generic_t;
    typedef typename igenfunct_t::parameter_list_t parameter_list_t;
    typedef typename generic_t::string_view string_t;

private:
    using MatchingFunc = std::function<std::string(const std::string&, const std::string&, const std::string&)>;
    MatchingFunc func_;

public:
    ExprtkGetWithPathFunction(const std::string& idenfier, MatchingFunc func) : igenfunct_t(idenfier, igenfunct_t::e_rtrn_string), func_(func) {}

    ExprtkGetWithPathFunction() : igenfunct_t("SSS", igenfunct_t::e_rtrn_string) {}

    inline numerical_type operator()(std::string& result, parameter_list_t parameters) override {
        result.clear();

        // check value cnt
        if (parameters.size() != 3) {
            return numerical_type(0);
        }

        // check value type
        for (std::size_t i = 0; i < parameters.size(); ++i) {
            generic_type& gt = parameters[i];
            if (generic_type::e_string != gt.type) {
                return numerical_type(0);
            }
        }
        std::string key1 = exprtk::to_str(string_t(parameters[0]));
        std::string key2 = exprtk::to_str(string_t(parameters[1]));
        std::string path_var = exprtk::to_str(string_t(parameters[2]));

        if (this->func_ != nullptr) {
            result = this->func_(key1, key2, path_var);
        }

        return numerical_type(0);
    }
};

enum class ExprtkFunctionType {
    Unknown,
    Gfunction,
    KeyMatch,
    KeyMatch2,
    KeyMatch3,
    KeyMatch4,
    KeyMatch5,
    RegexMatch,
    IpMatch,
    KeyGet,
    KeyGet2,
    KeyGet3,
};

class ExprtkFunctionFactory {
public:
    static std::shared_ptr<exprtk_func_t> GetExprtkFunction(ExprtkFunctionType type, int narg, std::shared_ptr<RoleManager> rm = nullptr) {
        std::string idenfier(narg, 'S');

        // Static map to act as an object pool
        static std::unordered_map<std::string, std::shared_ptr<exprtk_func_t>> pool;

        // Create a key for the object pool using the type and identifier
        std::string key = std::to_string(static_cast<int>(type)) + idenfier;

        // Check if the object already exists in the pool
        if (pool.find(key) != pool.end()) {
            // If it exists, return the existing object
            return pool[key];
        }

        // If it doesn't exist, create a new object
        std::shared_ptr<exprtk_func_t> func = nullptr;
        switch (type) {
            case ExprtkFunctionType::Gfunction:
                func = std::make_shared<ExprtkGFunction>(idenfier, rm);
                break;
            case ExprtkFunctionType::KeyMatch:
                func = std::make_shared<ExprtkMatchFunction>(idenfier, KeyMatch);
                break;
            case ExprtkFunctionType::KeyMatch2:
                func = std::make_shared<ExprtkMatchFunction>(idenfier, KeyMatch2);
                break;
            case ExprtkFunctionType::KeyMatch3:
                func = std::make_shared<ExprtkMatchFunction>(idenfier, KeyMatch3);
                break;
            case ExprtkFunctionType::KeyMatch4:
                func = std::make_shared<ExprtkMatchFunction>(idenfier, KeyMatch4);
                break;
            case ExprtkFunctionType::KeyMatch5:
                func = std::make_shared<ExprtkMatchFunction>(idenfier, KeyMatch5);
                break;
            case ExprtkFunctionType::IpMatch:
                func = std::make_shared<ExprtkMatchFunction>(idenfier, IPMatch);
                break;
            case ExprtkFunctionType::RegexMatch:
                func = std::make_shared<ExprtkMatchFunction>(idenfier, RegexMatch);
                break;
            case ExprtkFunctionType::KeyGet:
                func = std::make_shared<ExprtkGetFunction>(idenfier, KeyGet);
                break;
            case ExprtkFunctionType::KeyGet2:
                func = std::make_shared<ExprtkGetWithPathFunction>(idenfier, KeyGet2);
                break;
            case ExprtkFunctionType::KeyGet3:
                func = std::make_shared<ExprtkGetWithPathFunction>(idenfier, KeyGet3);
                break;
            default:
                func = nullptr;
        }

        // If a new object was created, add it to the pool
        if (func) {
            pool[key] = func;
        }
        pool.clear();
        // Return the newly created or existing object
        return func;
    }

};
} // namespace casbin

#endif