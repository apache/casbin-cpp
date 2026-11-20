<!--
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements. See the NOTICE file
distributed with this work for additional information
regarding copyright ownership. The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License. You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied. See the License for the
specific language governing permissions and limitations
under the License.
-->

# Releasing Apache Casbin C++ (incubating)

The release manager creates a candidate tag of the form `vX.Y.Z-rcN`. The
workflow assembles an unsigned source archive and its SHA-512 checksum. Check
the archive and licenses, sign the same archive and stage it for the project
and Incubator votes. Use the original approved artifacts when publishing the
release. Create the final tag at the approved commit after promotion.

The source release can be built with a C++17 compiler. When consuming the
installed CMake target, configure the consumer project to use C++17 or later.

A vcpkg port update or a Python bindings package requires its own artifact and
channel checks. If preparing a vcpkg update after approval, update its source
URL and SHA-512 together and build that port from the approved source.
