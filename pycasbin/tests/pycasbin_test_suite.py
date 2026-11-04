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

import unittest
import sys
import os
import pycasbin
import test_enforcer
import test_model
import test_config
import test_cached_enforcer
import test_synced_enforcer
import test_adapter

def suite():

    # top level directory cached on loader instance
    suite = unittest.TestSuite()
    loader = unittest.TestLoader()

    suite.addTest(loader.loadTestsFromModule(test_enforcer))
    suite.addTest(loader.loadTestsFromModule(test_model))
    suite.addTest(loader.loadTestsFromModule(test_config))
    suite.addTest(loader.loadTestsFromModule(test_cached_enforcer))
    suite.addTest(loader.loadTestsFromModule(test_adapter))
    #suite.addTest(loader.loadTestsFromModule(test_synced_enforcer))

    return suite


if __name__ == '__main__':
    runner = unittest.TextTestRunner(verbosity=2)
    test_suite = suite()
    result = runner.run(test_suite)
    if result.wasSuccessful() == False:
        sys.exit(1)
    sys.exit(0)
