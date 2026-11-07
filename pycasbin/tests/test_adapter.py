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

from logging import setLoggerClass
import pycasbin as casbin
from config_path import *
import unittest
import os

class TestAdapter(unittest.TestCase):

    def setUp(self):
        self.Adapter = None
        self.Model = None

    def cleanUp(self):
        self.Adapter = None
        self.Model = None

    def FileAdapterInit(self, path):
        self.Adapter = casbin.FileAdapter.NewFileAdapter(path)

    def ModelInit(self, model_path):
        self.Model = casbin.Model.NewModelFromFile(model_path)

    def test_NewFileAdapter(self):
        self.cleanUp()
        self.Adapter = casbin.FileAdapter.NewFileAdapter(basic_policy_path)
        self.assertIsNotNone(self.Adapter)

    def test_NewBatchFileAdapter(self):
        self.cleanUp()
        self.Adapter = casbin.BatchFileAdapter.NewBatchFileAdapter(basic_model_path)
        self.assertIsNotNone(self.Adapter)

    def test_FileAdapterLoadPolicy(self):
        self.cleanUp()
        self.FileAdapterInit(basic_policy_path)
        self.ModelInit(basic_model_path)
        self.Adapter.LoadPolicy(self.Model)

        FilePolicies = [["alice", "data1", "read"],
                        ["bob", "data2", "write"]]

        self.assertTrue(self.Model.HasPolicy('p', 'p', FilePolicies[0]))
        self.assertTrue(self.Model.HasPolicy('p', 'p', FilePolicies[1]))
