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
#include <sharemind/module-apis/api_0x1.h>
#include <sharemind/SyscallsCommon.h>

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

    const auto logger =
        LogHard::Logger(
            *static_cast<const LogHard::Logger *>(flog->facility),
            "[mod_keydb]");

    const SharemindModuleApi0x1Facility * fconsensus
            = c->getModuleFacility(c, "ConsensusService");

    SharemindConsensusFacility * consensusFacility = nullptr;
    if (fconsensus && fconsensus->facility) {
        consensusFacility =
            static_cast<SharemindConsensusFacility *>(fconsensus->facility);
    }

    try {
        if (!c->conf) {
            logger.error() << "No configuration given.";
            return SHAREMIND_MODULE_API_0x1_INVALID_MODULE_CONFIGURATION;
        }

        sharemind::ModuleData * mod =
            new sharemind::ModuleData(std::move(logger), consensusFacility);

        std::string error;
        if (!mod->load(c->conf, error)) {
            logger.error() << "Failed to parse configuration: " << error;
            delete mod;
            return SHAREMIND_MODULE_API_0x1_INVALID_MODULE_CONFIGURATION;
        }

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
    delete static_cast<sharemind::ModuleData *>(c->moduleHandle);
    #ifndef NDEBUG
    c->moduleHandle = nullptr; // Not needed, but may help debugging.
    #endif
}

#define SAMENAME(f) { #f, &(f) }

SHAREMIND_MODULE_API_0x1_SYSCALL_DEFINITIONS(
    SAMENAME(keydb_clean),
    SAMENAME(keydb_connect),
    SAMENAME(keydb_del),
    SAMENAME(keydb_disconnect),
    SAMENAME(keydb_get),
    SAMENAME(keydb_get_size),
    SAMENAME(keydb_scan),
    SAMENAME(keydb_set)
);

} // extern "C" {
