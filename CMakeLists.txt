#
# Copyright (C) Cybernetica
#
# Research/Commercial License Usage
# Licensees holding a valid Research License or Commercial License
# for the Software may use this file according to the written
# agreement between you and Cybernetica.
#
# GNU Lesser General Public License Usage
# Alternatively, this file may be used under the terms of the GNU Lesser
# General Public License version 3 as published by the Free Software
# Foundation and appearing in the file LICENSE.LGPLv3 included in the
# packaging of this file.  Please review the following information to
# ensure the GNU Lesser General Public License version 3 requirements
# will be met: http://www.gnu.org/licenses/lgpl-3.0.html.
#
# For further information, please contact us at sharemind@cyber.ee.
#

CMAKE_MINIMUM_REQUIRED(VERSION 3.0)
PROJECT(SharemindModKeyDb VERSION 0.3.0 LANGUAGES CXX)

INCLUDE("${CMAKE_CURRENT_SOURCE_DIR}/config.local" OPTIONAL)
INCLUDE("${CMAKE_CURRENT_BINARY_DIR}/config.local" OPTIONAL)

FIND_PACKAGE(SharemindCMakeHelpers 1.6 REQUIRED)

SET(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/CMakeIncludes/"
                      ${CMAKE_MODULE_PATH})
FIND_PACKAGE(Boost 1.62 REQUIRED)
FIND_PACKAGE(hiredis REQUIRED)
FIND_PACKAGE(LogHard 0.5.0 REQUIRED)
FIND_PACKAGE(SharemindDataStoreApi 0.1.0 REQUIRED)
FIND_PACKAGE(SharemindLibAccessControlProcessFacility 0.4.0 REQUIRED)
FIND_PACKAGE(SharemindLibConsensusService 0.2.0 REQUIRED)
FIND_PACKAGE(SharemindLibProcessFacility 0.2.0 REQUIRED)
FIND_PACKAGE(SharemindModuleApis 1.1.0 REQUIRED)
FIND_PACKAGE(SharemindPdkHeaders 0.5.0 REQUIRED)


# The module:
FILE(GLOB_RECURSE SharemindModKeyDb_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")
FILE(GLOB_RECURSE SharemindModKeyDb_HEADERS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.h")
SharemindAddSharedLibrary(ModKeyDb
    MODULE
    OUTPUT_NAME "sharemind_mod_keydb"
    SOURCES
        ${SharemindModKeyDb_SOURCES}
        ${SharemindModKeyDb_HEADERS}
)
TARGET_INCLUDE_DIRECTORIES(ModKeyDb PRIVATE ${HIREDIS_INCLUDE_DIRS})
TARGET_LINK_LIBRARIES(ModKeyDb
    PRIVATE
        Boost::boost
        ${HIREDIS_LIBRARIES}
        LogHard::LogHard
        Sharemind::LibAccessControlProcessFacility
        Sharemind::LibConsensusService
        Sharemind::DataStoreApi
        Sharemind::LibProcessFacility
        Sharemind::ModuleApis
        Sharemind::PdkHeaders
    )

# Configuration files:
INSTALL(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/packaging/configs/sharemind/"
        DESTINATION "/etc/sharemind/"
        COMPONENT "lib"
        EXCLUDE_FROM_ALL)

# Packaging:
SharemindSetupPackaging()
SharemindAddComponentPackage("lib"
    NAME "libsharemind-mod-keydb"
    DESCRIPTION "Sharemind KeyDB module"
    DEB_SECTION "libs"
    DEB_DEPENDS
        "libloghard (>= 0.5.0)"
        "libhiredis${HIREDIS_VERSION}"
        "libstdc++6 (>= 4.8.0)"
        "libc6 (>= 2.19)"
    DEB_EXTRA_CONTROL_FILES
        "${CMAKE_CURRENT_SOURCE_DIR}/packaging/debian/conffiles"
)
SharemindAddComponentPackage("debug"
    NAME "libsharemind-mod-keydb-dbg"
    DESCRIPTION "Sharemind KeyDB module debug symbols"
    DEB_SECTION "debug"
    DEB_DEPENDS
        "libsharemind-mod-keydb (= ${SharemindModKeyDb_DEB_lib_PACKAGE_VERSION})"
)
SharemindPackagingFinalize()

