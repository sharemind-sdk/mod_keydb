#
# Copyright (C) Cybernetica
#
# Research/Commercial License Usage
# Licensees holding a valid Research License or Commercial License
# for the Software may use this file according to the written
# agreement between you and Cybernetica.
#
# GNU General Public License Usage
# Alternatively, this file may be used under the terms of the GNU
# General Public License version 3.0 as published by the Free Software
# Foundation and appearing in the file LICENSE.GPL included in the
# packaging of this file.  Please review the following information to
# ensure the GNU General Public License version 3.0 requirements will be
# met: http://www.gnu.org/copyleft/gpl-3.0.html.
#
# For further information, please contact us at sharemind@cyber.ee.
#

################################################################################
#
# CMake script for finding hiredis.
# The default CMake search process is used to locate files.
#
# This script creates the following variables:
#  HIREDIS_FOUND: Boolean that indicates if the package was found
#  HIREDIS_INCLUDE_DIRS: Paths to the necessary header files
#  HIREDIS_LIBRARIES: Package libraries
#
################################################################################

# Find headers and libraries
FIND_PATH(
    HIREDIS_INCLUDE_DIR
    NAMES
        hiredis/hiredis.h
    HINTS
        $ENV{HIREDIS_ROOT}
        ${HIREDIS_ROOT}
    PATHS
        /usr/local
        /usr
        /opt/local
    PATH_SUFFIXES
        include
)

FIND_LIBRARY(
    HIREDIS_LIBRARY
    NAMES
        hiredis
    HINTS
        $ENV{HIREDIS_ROOT}
        ${HIREDIS_ROOT}
    PATHS
        /opt/local
        /usr/local
        /usr
    PATH_SUFFIXES
        lib
)

# Set HIREDIS_FOUND honoring the QUIET and REQUIRED arguments
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(
    hiredis
    "Could NOT find hiredis"
    HIREDIS_LIBRARY HIREDIS_INCLUDE_DIR)

FUNCTION(GET_HIREDIS_VERSION out)
    SET(srcFile "${CMAKE_CURRENT_BINARY_DIR}/hiredisVersion.cpp")
    FILE(WRITE "${srcFile}"  "#include <hiredis/hiredis.h>\n")
    FILE(APPEND "${srcFile}" "#include <iostream>\n")
    FILE(APPEND "${srcFile}" "#define S2(s) #s\n")
    FILE(APPEND "${srcFile}" "#define S(s) S2(s)\n")
    FILE(APPEND "${srcFile}" "using namespace std;\n")
    FILE(APPEND "${srcFile}"
         "int main() { cout << S(HIREDIS_SONAME) << endl; }\n")
    TRY_RUN(runResult compileResult "${CMAKE_CURRENT_BINARY_DIR}"
            "${srcFile}" RUN_OUTPUT_VARIABLE RUN_OUTPUT)
    IF("${compileResult}" AND (NOT "${runResult}"))
        STRING(STRIP  "${RUN_OUTPUT}" RUN_OUTPUT)
        SET(HIREDIS_VERSION "${RUN_OUTPUT}" PARENT_SCOPE)
    ENDIF()
ENDFUNCTION()

# Output variables
IF(HIREDIS_FOUND)
    # Include dirs
    SET(HIREDIS_INCLUDE_DIRS ${HIREDIS_INCLUDE_DIR})
    # Libraries
    SET(HIREDIS_LIBRARIES ${HIREDIS_LIBRARY})
    # Version
    GET_HIREDIS_VERSION(HIREDIS_VERSION)
ENDIF()

# Advanced options for not cluttering the cmake UIs:
MARK_AS_ADVANCED(HIREDIS_INCLUDE_DIR HIREDIS_LIBRARY HIREDIS_VERSION)
