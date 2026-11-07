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
from datetime import timedelta
import time

class TestSyncedEnforcer(unittest.TestCase):
    def setUp(self):
        self.initSyncedEnforcer(basic_model_path, basic_policy_path)

    def initSyncedEnforcer(self, model, policy):
        self.current_model = model
        self.current_policy = policy
        self.e = casbin.SyncedEnforcer(self.current_model, self.current_policy)

    def test_Sync(self):
        self.initSyncedEnforcer(basic_model_path, basic_policy_path)
        self.e.StartAutoLoadPolicy(timedelta(microseconds=200))
        self.assertEqual(self.e.Enforce(["alice", "data1", "read"]), True)
        self.assertEqual(self.e.Enforce(["alice", "data1", "write"]), False)
        self.assertEqual(self.e.Enforce(["alice", "data2", "read"]), False)
        self.assertEqual(self.e.Enforce(["alice", "data2", "write"]), False)
        self.assertEqual(self.e.Enforce(["bob", "data1", "read"]), False)
        self.assertEqual(self.e.Enforce(["bob", "data1", "write"]), False)
        self.assertEqual(self.e.Enforce(["bob", "data2", "read"]), False)
        self.assertEqual(self.e.Enforce(["bob", "data2", "write"]), True)

        time.sleep(2)
        e.StopAutoLoadPolicy()
    
    def test_StopLoadPolicy(self):
        self.initSyncedEnforcer(basic_model_path, basic_policy_path)
        self.e.StartAutoLoadPolicy(timedelta(microseconds=5))

        self.assertEqual(self.e.IsAutoLoadingRunning(), True)

        self.assertEqual(self.e.Enforce(["alice", "data1", "read"]), True)
        self.assertEqual(self.e.Enforce(["alice", "data1", "write"]), False)
        self.assertEqual(self.e.Enforce(["alice", "data2", "read"]), False)
        self.assertEqual(self.e.Enforce(["alice", "data2", "write"]), False)
        self.assertEqual(self.e.Enforce(["bob", "data1", "read"]), False)
        self.assertEqual(self.e.Enforce(["bob", "data1", "write"]), False)
        self.assertEqual(self.e.Enforce(["bob", "data2", "read"]), False)
        self.assertEqual(self.e.Enforce(["bob", "data2", "write"]), True)

        self.e.StopAutoLoadPolicy()

        time.sleep(1)
        self.assertEqual(self.e.IsAutoLoadingRunning(), False)
