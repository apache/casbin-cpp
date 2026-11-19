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

#include "casbin/pch.h"

#ifndef FILE_ADAPTER_CPP
#define FILE_ADAPTER_CPP

#include <fstream>

#include "casbin/exception/casbin_adapter_exception.h"
#include "casbin/exception/io_exception.h"
#include "casbin/exception/unsupported_operation_exception.h"
#include "casbin/persist/file_adapter/file_adapter.h"
#include "casbin/util/util.h"

namespace casbin {

// NewAdapter is the constructor for Adapter.
FileAdapter ::FileAdapter(std::string file_path) {
    this->file_path = file_path;
    this->filtered = false;
}

std::shared_ptr<casbin::FileAdapter> FileAdapter::NewFileAdapter(std::string file_path) {
    return std::make_shared<FileAdapter>(file_path);
}

// LoadPolicy loads all policy rules from the storage.
void FileAdapter ::LoadPolicy(const std::shared_ptr<Model>& model) {
    if (this->file_path == "")
        throw CasbinAdapterException("Invalid file path, file path cannot be empty");

    this->LoadPolicyFile(model, LoadPolicyLine);
}

// SavePolicy saves all policy rules to the storage.
void FileAdapter ::SavePolicy(const std::shared_ptr<Model>& model) {
    if (this->file_path == "") {
        throw CasbinAdapterException("Invalid file path, file path cannot be empty");
    }

    std::string tmp;

    for (std::unordered_map<std::string, std::shared_ptr<Assertion>>::iterator it = model->m["p"].assertion_map.begin(); it != model->m["p"].assertion_map.end(); it++) {
        for (auto& policy_value : it->second->policy) {
            tmp += it->first + ", ";
            tmp += ArrayToString(policy_value);
            tmp += "\n";
        }
    }

    for (std::unordered_map<std::string, std::shared_ptr<Assertion>>::iterator it = model->m["g"].assertion_map.begin(); it != model->m["g"].assertion_map.end(); it++) {
        for (auto& policy_value : it->second->policy) {
            tmp += it->first + ", ";
            tmp += ArrayToString(policy_value);
            tmp += "\n";
        }
    }

    return this->SavePolicyFile(RTrim(tmp, "\n"));
}

void FileAdapter ::LoadPolicyFile(const std::shared_ptr<Model>& model, std::function<void(std::string, const std::shared_ptr<Model>&)> handler) {
    std::ifstream in_file;
    try {
        in_file.open(this->file_path);
    } catch (const std::ifstream::failure e) {
        throw IOException("Cannot open file.");
    }

    std::string line;
    while (getline(in_file, line, '\n')) {
        line = Trim(line);
        handler(line, model);
    }

    in_file.close();
}

void FileAdapter ::SavePolicyFile(std::string text) {
    std::ofstream out_file;

    try {
        out_file.open(this->file_path, std::ios::out);
    } catch (const std::ifstream::failure e) {
        throw IOException("Cannot open file.");
    }

    if (out_file.is_open() == false) {
        throw IOException("Don't exit adapter file");
    }

    out_file << text;

    out_file.close();
}

// AddPolicy adds a policy rule to the storage.
void FileAdapter ::AddPolicy(std::string sec, std::string p_type, std::vector<std::string> rule) {
    throw UnsupportedOperationException("not implemented");
}

// RemovePolicy removes a policy rule from the storage.
void FileAdapter ::RemovePolicy(std::string sec, std::string p_type, std::vector<std::string> rule) {
    throw UnsupportedOperationException("not implemented");
}

// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
void FileAdapter ::RemoveFilteredPolicy(std::string sec, std::string p_type, int field_index, std::vector<std::string> field_values) {
    throw UnsupportedOperationException("not implemented");
}

// IsFiltered returns true if the loaded policy has been filtered.
bool FileAdapter ::IsFiltered() {
    return this->filtered;
}

// IsValid returns true if the loaded policy is valid.
bool FileAdapter ::IsValid() {
    return this->file_path != "";
}

} // namespace casbin

#endif // FILE_ADAPTER_CPP
