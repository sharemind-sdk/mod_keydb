#
# Copyright (C) 2016 Cybernetica
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
# CMake script for finding cpp_redis.
# The default CMake search process is used to locate files.
#
# This script creates the following variables:
#  CPP_REDIS_FOUND: Boolean that indicates if the package was found
#  CPP_REDIS_INCLUDE_DIRS: Paths to the necessary header files
#  CPP_REDIS_LIBRARIES: Package libraries
#
################################################################################

# Find headers and libraries
FIND_PATH(
    CPP_REDIS_INCLUDE_DIR
    NAMES
        cpp_redis/cpp_redis
    HINTS
        $ENV{CPP_REDIS_ROOT}
        ${CPP_REDIS_ROOT}
    PATHS
        /usr/local
        /usr
        /opt/local
    PATH_SUFFIXES
        include
)

FIND_LIBRARY(
    CPP_REDIS_LIBRARY
    NAMES
        cpp_redis
    HINTS
        $ENV{CPP_REDIS_ROOT}
        ${CPP_REDIS_ROOT}
    PATHS
        /opt/local
        /usr/local
        /usr
    PATH_SUFFIXES
        lib
)

# Set CPP_REDIS_FOUND honoring the QUIET and REQUIRED arguments
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(
    cpp_redis
    "Could NOT find cpp_redis"
    CPP_REDIS_LIBRARY CPP_REDIS_INCLUDE_DIR)

# Output variables
IF(CPP_REDIS_FOUND)
    # Include dirs
    SET(CPP_REDIS_INCLUDE_DIRS ${CPP_REDIS_INCLUDE_DIR})
    # Libraries
    SET(CPP_REDIS_LIBRARIES ${CPP_REDIS_LIBRARY})
ENDIF(CPP_REDIS_FOUND)

# Advanced options for not cluttering the cmake UIs:
MARK_AS_ADVANCED(CPP_REDIS_INCLUDE_DIR CPP_REDIS_LIBRARy)
