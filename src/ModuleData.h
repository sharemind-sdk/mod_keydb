/*
 * This file is a part of the Sharemind framework.
 * Copyright (C) Cybernetica AS
 *
 * All rights are reserved. Reproduction in whole or part is prohibited
 * without the written consent of the copyright owner. The usage of this
 * code is subject to the appropriate license agreement.
 */

#ifndef SHAREMIND_MOD_CONSENSUS_MODULEDATA_H
#define SHAREMIND_MOD_CONSENSUS_MODULEDATA_H

#include <sharemind/libconsensusservice.h>
#include <string>

struct __attribute__ ((visibility("internal"))) ModuleData {
    ModuleData(SharemindConsensusFacility & cf);
    SharemindConsensusFacility &consensusFacility;
    std::string configuration;
};

#endif /* SHAREMIND_MOD_CONSENSUS_MODULEDATA_H */
