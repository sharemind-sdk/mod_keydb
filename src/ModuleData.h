/*
 * This file is a part of the Sharemind framework.
 * Copyright (C) Cybernetica AS
 *
 * All rights are reserved. Reproduction in whole or part is prohibited
 * without the written consent of the copyright owner. The usage of this
 * code is subject to the appropriate license agreement.
 */

#ifndef SHAREMIND_MOD_KEYDB_MODULEDATA_H
#define SHAREMIND_MOD_KEYDB_MODULEDATA_H

#include <LogHard/Logger.h>
#include <sharemind/libconsensusservice.h>
#include <string>
#include <vector>

struct __attribute__ ((visibility("internal"))) ModuleData {
    ModuleData(const LogHard::Logger & logger,
        SharemindConsensusFacility & cf);

    const LogHard::Logger logger;
    SharemindConsensusFacility &consensusFacility;
    std::string host;
    unsigned int port;
};

#endif /* SHAREMIND_MOD_KEYDB_MODULEDATA_H */
