#  Copyright 2021 The casbin Authors. All Rights Reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

set(SOURCES
    src/main.cpp
    src/py_cached_enforcer.cpp
    src/py_enforcer.cpp
    src/py_model.cpp
    src/py_config.cpp
    src/py_synced_enforcer.cpp
    src/py_adapter.cpp
)

set(HEADERS
    src/py_casbin.h
)

add_library(pycasbin MODULE ${SOURCES} ${HEADERS})

target_include_directories(pycasbin PUBLIC ${CASBIN_INCLUDE_DIR})

set_target_properties(pycasbin PROPERTIES
    CXX_STANDARD 17
)

# For in-source versioning macro
add_definitions(-DPY_CASBIN_VERSION="${PY_CASBIN_VERSION}")

target_link_libraries(pycasbin
    PRIVATE
        pybind11::module 
        pybind11::lto
        pybind11::windows_extras
        casbin
        nlohmann_json::nlohmann_json
)

pybind11_extension(pycasbin)
pybind11_strip(pycasbin)
# For testing
# install(
#     TARGETS pycasbin
#     LIBRARY DESTINATION ${CMAKE_SOURCE_DIR}/tests/python
# )
