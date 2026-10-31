
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
include(FetchContent)

# Prefer a nlohmann_json that is already available on the system (this is what
# package managers such as vcpkg or Conan provide); only download a copy when
# there is none, so that packaged builds don't vendor their own.
option(CASBIN_FETCH_JSON "Always download nlohmann_json instead of using the system one" OFF)

if(NOT CASBIN_FETCH_JSON)
    find_package(nlohmann_json 3.10.1 CONFIG QUIET)
endif()

if(NOT nlohmann_json_FOUND)
    set(JSON_Install ON)

    FetchContent_Declare(
      json
      GIT_REPOSITORY https://github.com/nlohmann/json.git
      GIT_TAG v3.12.0
      DOWNLOAD_EXTRACT_TIMESTAMP FALSE
    )

    FetchContent_MakeAvailable(json)
endif()

set(json_FOUND TRUE)
