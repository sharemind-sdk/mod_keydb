/*
 * Copyright (C) 2016 Cybernetica
 *
 * Research/Commercial License Usage
 * Licensees holding a valid Research License or Commercial License
 * for the Software may use this file according to the written
 * agreement between you and Cybernetica.
 *
 * GNU General Public License Usage
 * Alternatively, this file may be used under the terms of the GNU
 * General Public License version 3.0 as published by the Free Software
 * Foundation and appearing in the file LICENSE.GPL included in the
 * packaging of this file.  Please review the following information to
 * ensure the GNU General Public License version 3.0 requirements will be
 * met: http://www.gnu.org/copyleft/gpl-3.0.html.
 *
 * For further information, please contact us at sharemind@cyber.ee.
 */

#include <cassert>
#include <LogHard/Logger.h>
#include <sharemind/libconsensusservice.h>
#include <sharemind/libmodapi/api_0x1.h>
#include <sharemind/SyscallsCommon.h>
#include <sstream>
#include "ModuleData.h"
#include "Syscalls.h"

extern "C" {

SHAREMIND_MODULE_API_MODULE_INFO("keydb",
                                 0x00010000,   /* Version 0.1.0.0 */
                                 0x1);         /* Support API version 1. */

SHAREMIND_MODULE_API_0x1_INITIALIZER(c) __attribute__ ((visibility("default")));
SHAREMIND_MODULE_API_0x1_INITIALIZER(c) {
    assert(c);

    const SharemindModuleApi0x1Facility * flog = c->getModuleFacility(c, "Logger");
    if (!flog || !flog->facility)
        return SHAREMIND_MODULE_API_0x1_MISSING_FACILITY;

    const LogHard::Logger & logger =
            *static_cast<const LogHard::Logger *>(flog->facility);

    const SharemindModuleApi0x1Facility * fconsensus
            = c->getModuleFacility(c, "ConsensusService");
    if (!fconsensus || !fconsensus->facility)
        return SHAREMIND_MODULE_API_0x1_MISSING_FACILITY;

    SharemindConsensusFacility * consensusFacility =
        static_cast<SharemindConsensusFacility *>(fconsensus->facility);

    try {
        ModuleData * mod = new ModuleData(logger, *consensusFacility);

        /* parse configuration
         * HOST PORT
         */
        if (!c->conf) {
            mod->logger.error() << "No configuration given.";
            delete mod;
            return SHAREMIND_MODULE_API_0x1_INVALID_MODULE_CONFIGURATION;
        }

        std::istringstream configuration(c->conf);
        std::string host;
        unsigned int port;
        configuration >> host >> port;
        if (!configuration || !configuration.eof()) {
            delete mod;
            return SHAREMIND_MODULE_API_0x1_INVALID_MODULE_CONFIGURATION;
        }

        mod->host = host;
        mod->port = port;
        c->moduleHandle = mod;
        return SHAREMIND_MODULE_API_0x1_OK;
    } catch (...) {
        return sharemind::catchModuleApiErrors();
    }
}

SHAREMIND_MODULE_API_0x1_DEINITIALIZER(c)
        __attribute__ ((visibility("default")));
SHAREMIND_MODULE_API_0x1_DEINITIALIZER(c) {
    assert(c);
    assert(c->moduleHandle);
    delete static_cast<ModuleData *>(c->moduleHandle);
    #ifndef NDEBUG
    c->moduleHandle = nullptr; // Not needed, but may help debugging.
    #endif
}

#define SAMENAME(f) { #f, &(f) }

SHAREMIND_MODULE_API_0x1_SYSCALL_DEFINITIONS(
    SAMENAME(keydb_connect),
    SAMENAME(keydb_disconnect),
    SAMENAME(keydb_set),
    SAMENAME(keydb_get_size),
    SAMENAME(keydb_get),
    SAMENAME(keydb_del),
    SAMENAME(keydb_scan),
    SAMENAME(keydb_intersection)
);

} // extern "C" {
