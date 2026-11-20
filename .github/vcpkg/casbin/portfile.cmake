# Template for a separate vcpkg port update. Fill the version and SHA-512
# from the approved source for that update and verify the URL and hash.

vcpkg_check_linkage(ONLY_STATIC_LIBRARY)

vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO casbin/casbin-cpp
    REF "v${VERSION}"
    SHA512 @SHA512@
    HEAD_REF master
)

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
        # Everything below pulls its dependencies in with FetchContent, which a
        # port build has no network for. nlohmann_json is the one real
        # dependency and comes from vcpkg instead.
        -DCASBIN_BUILD_TEST=OFF
        -DCASBIN_BUILD_BENCHMARK=OFF
        -DCASBIN_BUILD_PYTHON_BINDINGS=OFF
        -DCASBIN_INSTALL=ON
)

vcpkg_cmake_install()

vcpkg_cmake_config_fixup(PACKAGE_NAME casbin CONFIG_PATH lib/cmake/casbin)

file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include")

vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/LICENSE")
