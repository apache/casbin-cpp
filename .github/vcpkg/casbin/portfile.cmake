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

# Template: replace @VERSION@ and @SHA512@ only after Apache approval.
vcpkg_check_linkage(ONLY_STATIC_LIBRARY)
vcpkg_download_distfile(ARCHIVE
    URLS "https://downloads.apache.org/incubator/casbin/cpp-@VERSION@-incubating/apache-casbin-cpp-@VERSION@-incubating-src.tar.gz"
    FILENAME "apache-casbin-cpp-@VERSION@-incubating-src.tar.gz"
    SHA512 @SHA512@
)
vcpkg_extract_source_archive(SOURCE_PATH ARCHIVE "${ARCHIVE}")
vcpkg_cmake_configure(SOURCE_PATH "${SOURCE_PATH}" OPTIONS
    -DCASBIN_BUILD_TEST=OFF -DCASBIN_BUILD_BENCHMARK=OFF
    -DCASBIN_BUILD_PYTHON_BINDINGS=OFF -DCASBIN_INSTALL=ON)
vcpkg_cmake_install()
vcpkg_cmake_config_fixup(PACKAGE_NAME casbin CONFIG_PATH lib/cmake/casbin)
file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include")
vcpkg_install_copyright(FILE_LIST "${CURRENT_PACKAGES_DIR}/share/casbin/LICENSE" "${CURRENT_PACKAGES_DIR}/share/casbin/NOTICE" "${CURRENT_PACKAGES_DIR}/share/casbin/DISCLAIMER")
