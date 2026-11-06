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

class TestEnforcer(unittest.TestCase):
    def setUp(self):
        self.initEnforcer(rbac_with_domains_model_path, rbac_with_domains_policy_path)

    def initEnforcer(self, model, policy):
        self.current_model = model
        self.current_policy = policy
        self.e = casbin.Enforcer(self.current_model, self.current_policy)

    def tearDown(self):
        self.e = None
    
    def test_FileAdapterEnforcer(self):
        self.fileAdapter = casbin.FileAdapter.NewFileAdapter(rbac_with_domains_policy_path)
        self.e = casbin.Enforcer(rbac_with_domains_model_path, self.fileAdapter)

        self.assertIsNotNone(self.fileAdapter)
        self.assertIsNotNone(self.e)

    def test_BatchFileAdapterEnforcer(self):
        self.fileAdapter = casbin.BatchFileAdapter.NewBatchFileAdapter(rbac_with_domains_policy_path)
        self.e = casbin.Enforcer(rbac_with_domains_model_path, self.fileAdapter)

        self.assertIsNotNone(self.fileAdapter)
        self.assertIsNotNone(self.e)

    def test_FourParams(self):
        self.initEnforcer(rbac_with_domains_model_path, rbac_with_domains_policy_path)

        self.assertEqual(self.e.Enforce(['alice', 'domain1', 'data1', 'read']), True)
        self.assertEqual(self.e.Enforce(['alice', 'domain1', 'data1', 'write']), True)
        self.assertEqual(self.e.Enforce(['alice', 'domain1', 'data2', 'read']), False)
        self.assertEqual(self.e.Enforce(['alice', 'domain1', 'data2', 'write']), False)
        self.assertEqual(self.e.Enforce(['bob', 'domain2', 'data1', 'read']), False)
        self.assertEqual(self.e.Enforce(['bob', 'domain2', 'data1', 'write']), False)
        self.assertEqual(self.e.Enforce(['bob', 'domain2', 'data2', 'read']), True)
        self.assertEqual(self.e.Enforce(['bob', 'domain2', 'data2', 'write']), True)

    def test_ThreeParams(self):
        self.initEnforcer(basic_model_without_spaces_path, basic_policy_path)

        self.assertEqual(self.e.Enforce([ 'alice', 'data1', 'read' ]), True)
        self.assertEqual(self.e.Enforce([ 'alice', 'data1', 'write' ]), False)
        self.assertEqual(self.e.Enforce([ 'alice', 'data2', 'read' ]), False)
        self.assertEqual(self.e.Enforce([ 'alice', 'data2', 'write' ]), False)
        self.assertEqual(self.e.Enforce([ 'bob', 'data1', 'read' ]), False)
        self.assertEqual(self.e.Enforce([ 'bob', 'data1', 'write' ]), False)
        self.assertEqual(self.e.Enforce([ 'bob', 'data2', 'read' ]), False)
        self.assertEqual(self.e.Enforce([ 'bob', 'data2', 'write' ]), True)

    def test_VectorParams(self):
        self.initEnforcer(basic_model_without_spaces_path, basic_policy_path)

        self.assertEqual(self.e.Enforce([ 'alice', 'data1', 'read' ]), True)
        self.assertEqual(self.e.Enforce([ 'alice', 'data1', 'write' ]), False)
        self.assertEqual(self.e.Enforce([ 'alice', 'data2', 'read' ]), False)
        self.assertEqual(self.e.Enforce([ 'alice', 'data2', 'write' ]), False)
        self.assertEqual(self.e.Enforce([ 'bob', 'data1', 'read' ]), False)
        self.assertEqual(self.e.Enforce([ 'bob', 'data1', 'write' ]), False)
        self.assertEqual(self.e.Enforce([ 'bob', 'data2', 'read' ]), False)
        self.assertEqual(self.e.Enforce([ 'bob', 'data2', 'write' ]), True)
