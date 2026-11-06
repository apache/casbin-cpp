# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

import pycasbin as casbin
from config_path import *
import unittest

class TestModel(unittest.TestCase):

    def setUp(self):
        self.model = None
        self.config = None

    def cleanUp(self):
        self.model = None
        self.config = None

    def tearDown(self):
        self.model = None
        self.config = None

    def test_NewModel(self):
        self.cleanUp()
        self.model = casbin.Model.NewModel()
        self.assertIsNotNone(self.model)

    def test_NewModelFromFile(self):
        self.cleanUp()
        self.model = casbin.Model.NewModelFromFile(basic_model_path)
        self.assertIsNotNone(self.model)

    def test_NewModelFromString(self):
        self.cleanUp()
        model_string = """[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act"""
        self.model = casbin.Model.NewModelFromString(model_string)
        self.assertIsNotNone(self.model)

    def test_LoadModelFromConfig(self):
        self.cleanUp()
        self.config = casbin.Config.NewConfig(basic_model_path)
        self.model = casbin.Model.NewModel()
        self.model.LoadModelFromConfig(self.config)
        self.model = casbin.Model.NewModel()
        self.config = casbin.Config.NewConfigFromText('')
        # self.assertRaises('', model.LoadModelFromConfig(basic_config))

    def test_HasSection(self):
        self.cleanUp()
        self.config = casbin.Config.NewConfig(basic_model_path)
        self.model = casbin.Model.NewModel()
        self.model.LoadModelFromConfig(self.config)
        for required_section in casbin.Model.required_sections:
            self.assertTrue(self.model.HasSection(required_section))

        self.cleanUp()
        self.model = casbin.Model.NewModel()
        self.config = casbin.Config.NewConfigFromText('')
        # self.assertRaises('', model.LoadModelFromConfig(config))

        for required_section in casbin.Model.required_sections:
            self.assertFalse(self.model.HasSection(required_section))

    def test_ModelAddDef(self):
        self.cleanUp()
        self.model = casbin.Model.NewModel()
        s = 'r'
        v = 'sub, obj, act'

        self.assertTrue(self.model.AddDef(s, s, v))

        self.assertFalse(self.model.AddDef(s, s, ''))
