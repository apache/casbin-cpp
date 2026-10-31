/*
 * Copyright 2022 The casbin Authors. All Rights Reserved.
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
#include "casbin/model/evaluator.h"

#include <regex>

#include "casbin/util/util.h"

namespace casbin {
bool ExprtkEvaluator::Eval(const std::string& expression_string) {
    expression.register_symbol_table(symbol_table);
    if (enable_get) {
        expression.register_symbol_table(glbl_variable_symbol_table);
    }

    if (this->expression_string_ != expression_string) {
        this->expression_string_ = expression_string;
        // replace (&& -> and), (|| -> or)
        auto replaced_string = std::regex_replace(expression_string, std::regex("&&"), "and");
        replaced_string = std::regex_replace(replaced_string, std::regex("\\|{2}"), "or");
        // replace string "" -> ''
        replaced_string = std::regex_replace(replaced_string, std::regex("\""), "\'");

        return parser.compile(replaced_string, expression);
    }

    return this->parser.error_count() == 0;
}

void ExprtkEvaluator::InitialObject(const std::string& identifier) {
    // symbol_table.add_stringvar("");
}

void ExprtkEvaluator::EnableGet(const std::string& identifier) {
    enable_get = true;
    if (identifier.empty()) {
        glbl_variable_symbol_table.add_stringvar("key_get_result", key_get_result);
    } else {
        glbl_variable_symbol_table.add_stringvar(identifier, key_get_result);
    }
}

void ExprtkEvaluator::PushObjectString(const std::string& target, const std::string& proprity, const std::string& var) {
    auto identifier = target + "." + proprity;

    this->AddIdentifier(identifier, var);
}

void ExprtkEvaluator::PushObjectJson(const std::string& target, const std::string& proprity, const nlohmann::json& var) {
    auto identifier = target + "." + proprity;
    
    // Recursively flatten JSON object into dot-notation identifiers
    if (var.is_object()) {
        for (auto& [key, value] : var.items()) {
            PushObjectJson(identifier, key, value);
        }
    } else if (var.is_string()) {
        this->AddIdentifier(identifier, var.get<std::string>());
    } else if (var.is_number()) {
        // Get as double first to preserve precision, then cast to numerical_type
        this->AddNumericIdentifier(identifier, static_cast<numerical_type>(var.get<double>()));
    } else if (var.is_boolean()) {
        this->AddNumericIdentifier(identifier, static_cast<numerical_type>(var.get<bool>() ? 1 : 0));
    }
    // For other types (arrays, null, etc.), we skip them as they're not supported in the expression evaluator
}

void ExprtkEvaluator::LoadFunctions() {
    AddFunction("keyMatch", ExprtkFunctionFactory::GetExprtkFunction(ExprtkFunctionType::KeyMatch, 2));
    AddFunction("keyMatch2", ExprtkFunctionFactory::GetExprtkFunction(ExprtkFunctionType::KeyMatch2, 2));
    AddFunction("keyMatch3", ExprtkFunctionFactory::GetExprtkFunction(ExprtkFunctionType::KeyMatch3, 2));
    AddFunction("keyMatch4", ExprtkFunctionFactory::GetExprtkFunction(ExprtkFunctionType::KeyMatch4, 2));
    AddFunction("keyMatch5", ExprtkFunctionFactory::GetExprtkFunction(ExprtkFunctionType::KeyMatch5, 2));
    AddFunction("regexMatch", ExprtkFunctionFactory::GetExprtkFunction(ExprtkFunctionType::RegexMatch, 2));
    AddFunction("ipMatch", ExprtkFunctionFactory::GetExprtkFunction(ExprtkFunctionType::IpMatch, 2));
    AddFunction("keyGet", ExprtkFunctionFactory::GetExprtkFunction(ExprtkFunctionType::KeyGet, 2));
    AddFunction("keyGet2", ExprtkFunctionFactory::GetExprtkFunction(ExprtkFunctionType::KeyGet2, 3));
    AddFunction("keyGet3", ExprtkFunctionFactory::GetExprtkFunction(ExprtkFunctionType::KeyGet3, 3));
}

void ExprtkEvaluator::LoadGFunction(std::shared_ptr<RoleManager> rm, const std::string& name, int narg) {
    auto func = ExprtkFunctionFactory::GetExprtkFunction(ExprtkFunctionType::Gfunction, narg, rm);
    this->AddFunction(name, func);
}

void ExprtkEvaluator::ProcessFunctions(const std::string& expression) {
}

Type ExprtkEvaluator::CheckType() {
    if (parser.error_count() != 0) {
        throw parser.error();
    }
    if (expression.value() == float(0) || expression.value() == float(1)) {
        return Type::Bool;
    } else {
        return Type::Float;
    }
}

bool ExprtkEvaluator::GetBoolean() {
    return bool(this->expression);
}

float ExprtkEvaluator::GetFloat() {
    return expression.value();
}

std::string ExprtkEvaluator::GetString() {
    const numerical_type result = expression.value();
    return key_get_result;
}

void ExprtkEvaluator::Clean(AssertionMap& section, bool after_enforce) {
    if (!after_enforce) {
        return;
    }

    this->symbol_table.clear();
    this->glbl_variable_symbol_table.clear();
    this->expression_string_ = "";
    this->Functions.clear();
    this->identifiers_.clear();
    this->numeric_identifiers_.clear();
}

void ExprtkEvaluator::AddFunction(const std::string& func_name, std::shared_ptr<exprtk_func_t> func) {
    if (func != nullptr) {
        this->Functions.push_back(func);
        symbol_table.add_function(func_name, *func);
    }
}

void ExprtkEvaluator::PrintSymbol() {
    std::vector<std::string> var_list;
    symbol_table.get_stringvar_list(var_list);

    printf("Current symboltable: \n");
    for (auto& var : var_list) {
        printf(" %s: %s\n", var.c_str(), symbol_table.get_stringvar(var)->ref().c_str());
    }
    printf("Current error: %s\n", parser.error().c_str());
    // printf("Current exprsio string: %s\n", parser.current_token);
    printf("Current value: %d\n", bool(this->expression));
}

std::unordered_map<std::string, std::string> ExprtkEvaluator::requestValues() const {
    std::vector<std::string> var_list;
    symbol_table.get_stringvar_list(var_list);
    std::unordered_map<std::string, std::string> result;
    for (const auto& e : var_list ) {
       if (e[0] == 'r') {
            auto token = e.substr(2, e.size() - 2);
	    auto value = symbol_table.get_stringvar("r." + token)->ref().c_str();
            result.emplace(token, value);
        }
    }
    return result;
}


void ExprtkEvaluator::AddIdentifier(const std::string& identifier, const std::string& var) {
    if (!symbol_table.symbol_exists(identifier)) {
        identifiers_[identifier] = std::make_unique<std::string>("");
        this->symbol_table.add_stringvar(identifier, *identifiers_[identifier]);
    }
    symbol_table.get_stringvar(identifier)->ref() = var;
}

void ExprtkEvaluator::AddNumericIdentifier(const std::string& identifier, numerical_type value) {
    if (!symbol_table.symbol_exists(identifier)) {
        numeric_identifiers_[identifier] = std::make_unique<numerical_type>(0);
        this->symbol_table.add_variable(identifier, *numeric_identifiers_[identifier]);
    }
    *numeric_identifiers_[identifier] = value;
}

} // namespace casbin
