#
# This file is a part of the Sharemind framework.
# Copyright (C) Cybernetica AS
#
# All rights are reserved. Reproduction in whole or part is prohibited
# without the written consent of the copyright owner. The usage of this
# code is subject to the appropriate license agreement.
#
CMAKE_MINIMUM_REQUIRED(VERSION 2.8.12)
PROJECT(SHAREMIND_MOD_KEYDB)
SET(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/CMakeIncludes/"
                      ${CMAKE_MODULE_PATH})

SET(SHAREMIND_MOD_KEYDB_VERSION "0.1.0")

INCLUDE("${CMAKE_CURRENT_SOURCE_DIR}/config.local" OPTIONAL)
INCLUDE("${CMAKE_CURRENT_BINARY_DIR}/config.local" OPTIONAL)

ADD_COMPILE_OPTIONS(
  "-std=c++11" "-Wall" "-Wextra" "-O2" "-fPIC"
  "$<$<NOT:$<STREQUAL:$<CONFIGURATION>,Release>>:-ggdb>"
  "$<$<NOT:$<STREQUAL:$<CONFIGURATION>,Release>>:-fno-omit-frame-pointer>"
  "$<$<STREQUAL:$<CONFIGURATION>,Release>:-DNDEBUG>"
  "$<$<STREQUAL:$<CONFIGURATION>,Release>:-fomit-frame-pointer>"
)

FIND_PACKAGE(cpp_redis REQUIRED)
FIND_PACKAGE(LogHard REQUIRED)
FIND_PACKAGE(SharemindLibConsensusService REQUIRED)
FIND_PACKAGE(SharemindLibDataStoreManager REQUIRED)
FIND_PACKAGE(SharemindLibDbCommon REQUIRED)
FIND_PACKAGE(SharemindLibmodapi REQUIRED)
FIND_PACKAGE(SharemindPdkHeaders REQUIRED)
INCLUDE_DIRECTORIES(
    ${CPP_REDIS_INCLUDE_DIRS}
    ${LogHard_INCLUDE_DIRS}
    ${SharemindLibConsensusService_INCLUDE_DIRS}
    ${SharemindLibDataStoreManager_INCLUDE_DIRS}
    ${SharemindLibDbCommon_INCLUDE_DIRS}
    ${SharemindLibmodapi_INCLUDE_DIRS}
    ${SharemindPdkHeaders_INCLUDE_DIRS}
)

ADD_DEFINITIONS(
    "-D__STDC_LIMIT_MACROS"
    "-D__STDC_CONSTANT_MACROS"
    "-D__STDC_FORMAT_MACROS"
    ${LogHard_DEFINITIONS}
    ${SharemindLibConsensusService_DEFINITIONS}
    ${SharemindLibDataStoreManager_DEFINITIONS}
    ${SharemindLibDbCommon_DEFINITIONS}
    ${SharemindLibmodapi_DEFINITIONS}
    ${SharemindPdkHeaders_DEFINITIONS}
)

FILE(GLOB_RECURSE KEYDB_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")
FILE(GLOB_RECURSE KEYDB_HEADERS_P "${CMAKE_CURRENT_SOURCE_DIR}/src/*.h")

ADD_LIBRARY(sharemind_mod_keydb MODULE
            ${KEYDB_SOURCES} ${KEYDB_HEADERS} ${KEYDB_HEADERS_P})
TARGET_LINK_LIBRARIES(sharemind_mod_keydb
    ${CPP_REDIS_LIBRARIES}
    ${LogHard_LIBRARIES}
    ${SharemindLibConsensusService_LIBRARIES}
    ${SharemindLibDbCommon_LIBRARIES}
)

INSTALL(TARGETS sharemind_mod_keydb LIBRARY DESTINATION "lib")

SET(SHAREMIND_MOD_KEYDB_INSTALL_INCLUDE_DIRS
    "${CMAKE_INSTALL_PREFIX}/include"
    ${SharemindMiner_Dsa_INCLUDE_DIRS})
SET(SHAREMIND_MOD_KEYDB_INSTALL_LIBRARIES ${SharemindMiner_Dsa_LIBRARIES})
SET(SHAREMIND_MOD_KEYDB_INSTALL_DEFINITIONS
    ${SharemindMiner_Dsa_DEFINITIONS}
    "-D__STDC_LIMIT_MACROS"
    "-D__STDC_CONSTANT_MACROS"
    "-D__STDC_FORMAT_MACROS"
)
