<!--
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
-->

# Third-party source and build inputs

The complete license texts and their exact file scopes are in LICENSE.
This inventory distinguishes bundled source from dependencies obtained during
a build; a dependency's build directory is not part of the source release.

| Material | Source scope | Treatment |
| --- | --- | --- |
| ExprTk, Arash Partow | include/casbin/exprtk/exprtk.hpp | Retain the original MIT header and add its complete grant in LICENSE. The checked-in file is the project's historical copy introduced with its 0.0.3 update, not asserted to be byte-identical to today's upstream tag. |
| Go net IP parsing adaptations | casbin/ip_parser/ and include/casbin/ip_parser/ | Preserve/restore the Go copyright and BSD terms for the derived portions; Casbin-specific contributions retain their own Apache terms. Compare the historical introduction with Go net/ip.go and net/parse.go when reviewing provenance. |
| pybind/cmake_example build helper | setup.py | Retain its BSD attribution and terms in LICENSE; Casbin package metadata changes are separate contributions. |
| github/gitignore VisualStudio template | .gitignore | CC0 1.0; preserve the template's origin link and include CC0 in LICENSE. |
| Casbin logo and policy/test fixtures | assets/images/ and examples/ | Project assets and contributed fixtures; not third-party dependencies. |

The upstream-selected build versions are unchanged. These commits record
the inspected snapshots; this patch does not replace the upstream tag refs
with immutable build pins:

| Dependency | Version | Commit | Purpose / declared license |
| --- | --- | --- | --- |
| nlohmann/json | 3.12.0 | 55f93686c01528224f448c19128836e7df245f72 | Public header dependency / MIT; installed system packages >=3.10.1 remain supported |
| googletest | 1.18.0 | 063de7e9578f82b369302001269680b4b1553359 | Tests only / BSD-3-Clause |
| google/benchmark | 1.10.0 | a6b4a9f00b36c19af9997d68a1cf6e0b5b3d032c | Optional benchmarks / Apache-2.0; inspect its own NOTICE for separate binary distribution |
| pybind11 | 3.1.0 | 97bf890db679505a14dfe547a5e77bb2bd05dc90 | Optional local Python binding / BSD-3-Clause |

An installed static library and the optional Python extension contain compiled
Casbin and ExprTk/IP parsing code; distribute the matching LICENSE, NOTICE and
DISCLAIMER with them. If packaging additional third-party binaries, account
for those actual contents independently.

License texts under `licenses/` accompany local convenience builds that compile nlohmann/json and pybind11; their implementations are fetched separately and are not bundled in this source release. Installed C++ legal material includes the compiled JSON dependency and omits source-only build-helper/template terms.
