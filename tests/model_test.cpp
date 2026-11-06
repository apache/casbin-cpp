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

/* This is a test file for testing built in functions in casbin */

#include <casbin/casbin.h>
#include <gtest/gtest.h>

#include <fstream>

#include "config_path.h"

namespace {

std::shared_ptr<casbin::Config> basic_config;
void InitTest() { basic_config = casbin::Config::NewConfig(basic_model_path); }

TEST(TestModel, TestNewModel) {
    std::shared_ptr<casbin::Model> model = casbin::Model::NewModel();
    ASSERT_NE(model, nullptr);
}

TEST(TestModel, TestNewModelFromFile) {
    std::shared_ptr<casbin::Model> model = casbin::Model::NewModelFromFile(basic_model_path);
    ASSERT_NE(model, nullptr);
}

TEST(TestModel, TestNewModelFromString) {
    std::ifstream infile;
    infile.open(basic_model_path);
    std::string content;
    std::getline(infile, content, '\0');
    std::shared_ptr<casbin::Model> model = casbin::Model::NewModelFromString(content);

    ASSERT_NE(model, nullptr);
}

TEST(TestModel, TestLoadModelFromConfig) {
    InitTest();
    std::shared_ptr<casbin::Model> model = casbin::Model::NewModel();
    model->LoadModelFromConfig(basic_config);

    model = casbin::Model::NewModel();
    std::shared_ptr<casbin::Config> config = casbin::Config::NewConfigFromText("");
    try {
        model->LoadModelFromConfig(config);
        FAIL();
    } catch (casbin::MissingRequiredSections e) {
    }
}

TEST(TestModel, TestHasSection) {
    InitTest();
    std::shared_ptr<casbin::Model> model = casbin::Model::NewModel();
    model->LoadModelFromConfig(basic_config);

    for (int i = 0; i < (casbin::Model::required_sections).size(); i++) {
        ASSERT_TRUE(model->HasSection((casbin::Model::required_sections)[i]));
    }

    model = casbin::Model::NewModel();
    std::shared_ptr<casbin::Config> config = casbin::Config::NewConfigFromText("");
    try {
        model->LoadModelFromConfig(config);
        FAIL();
    } catch (casbin::MissingRequiredSections e) {
    }

    for (const auto& section : casbin::Model::required_sections) ASSERT_FALSE(model->HasSection(section));
}

TEST(TestModel, TestModel_AddDef) {
    std::shared_ptr<casbin::Model> model = casbin::Model::NewModel();
    std::string s = "r";
    std::string v = "sub, obj, act";

    bool ok = model->AddDef(s, s, v);
    ASSERT_TRUE(ok);

    ok = model->AddDef(s, s, "");
    ASSERT_FALSE(ok);
}

} // namespace
