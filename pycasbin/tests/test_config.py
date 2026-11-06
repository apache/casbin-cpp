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

class TestConfig(unittest.TestCase):

    def setUp(self):
        self.config = None

    def tearDown(self):
        self.config = None

    def test_Debug(self):
        self.config = casbin.Config.NewConfig(testini_path)
        self.assertTrue(self.config.GetBool('debug'))

    def test_URL(self):
        self.config = casbin.Config.NewConfig(testini_path)
        self.assertEqual(self.config.GetString('url'), 'act.wiki')

    def test_Redis(self):
        self.config = casbin.Config.NewConfig(testini_path)
        values = self.config.GetStrings('redis::redis.key')
        self.assertEqual('push1', values[0])
        self.assertEqual('push2', values[1])
