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

# Releasing Apache Casbin (Incubating) C++

The current preparation targets 1.68.0. Keep CMake, the optional local Python
binding and the release tag at the same version. Source archives are named
`apache-casbin-cpp-X.Y.Z-incubating-src.tar.gz`; installed CMake consumers keep
using `find_package(casbin)` and `casbin::casbin`.

## Prepare and review

Complete the source, dependency, licensing, packaging and workflow review in
one preparation change. Build and test a clean extraction, install it into a
temporary prefix and test a separate C++17 consumer. Test the optional local
Python binding independently. See LICENSE for the exact third-party scopes;
downloaded CMake dependencies are not vendored in the source distribution.

The source includes local binding build metadata named `pycasbin`; the module
is also imported as `pycasbin`. This is distinct from the pure Python Casbin
implementation. No PyPI upload is configured here. The binding wheel must
include LICENSE, NOTICE and DISCLAIMER and must derive from reviewed source.

## Candidate

After review and merge, verify the exact commit and CI before the release
manager creates `vX.Y.Z-rcN` (N starts at 1). The release workflow exports that
commit without version stamping, adds SHA-512 and creates a GitHub prerelease
with `latest=false` and the incubation disclaimer. This is an unsigned
candidate, not a formal release. It never publishes a package registry or
opens a vcpkg PR.

The release manager reviews these exact archives, signs them, verifies the
signatures with the published project KEYS, and stages the originals in the
Apache development distribution area. Supply all source archive, signature,
checksum, commit/tag, KEYS and verification links for review. Candidate and
formal source filenames include `incubating`.

## Votes and formal publication

Seek public project/PPMC endorsement and Incubator PMC approval for these
exact source bytes. They can be coordinated with other Casbin components,
but candidate scope, votes and results stay explicit for each component and
voting body. See the current
[Incubation Policy](https://incubator.apache.org/policy/incubation.html#releases)
and [ASF release policy](https://www.apache.org/legal/release-policy.html).
Changed source requires a new candidate and fresh applicable votes.

Once approved and publication is authorized, promote the reviewed ASF
originals, including their existing signatures and checksums, into
`https://downloads.apache.org/incubator/casbin/cpp-X.Y.Z-incubating/`.
Do not rebuild or replace the approved archives. Create the final tag pointing
at the approved candidate commit; a final tag push does not publish anything.

The optional final GitHub publication is a manual workflow dispatch from
master, with the existing final tag and the public project and IPMC result
URLs. It downloads the approved ASF source and sidecars, validates SHA-512,
verifies the signature in an isolated keyring populated from the project KEYS,
and compares every file's content and mode with the tag before attaching the
original files. URL validation is not a substitute for a human checking vote
scope, voter qualification or approval. The workflow refuses existing GitHub
releases and nonempty output directories; it does not overwrite assets.

Check partial publication before any retry. A successful upload in one channel
does not establish completion of another. No signing private keys enter CI.

## vcpkg

The existing compatible port identity is `casbin`. After the source release,
render `.github/vcpkg/casbin/portfile.cmake` and `vcpkg.json` with the approved
version and the SHA-512 of the ASF original. The port downloads that original,
builds with external nlohmann-json and installs the matching legal files.
Validate the port, its installed consumer and version database against the
current vcpkg tooling before opening a separate registry PR. There is no
automatic registry PR or force-push in this release workflow.

Publish the final download links and announcement only after their respective
checks and authorizations. Inspect the incubation display on GitHub and the
registry separately; local README changes do not update historical releases.
