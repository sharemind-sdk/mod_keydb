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

#include <cpp_redis/redis_client.hpp>
#include <LogHard/Logger.h>
#include <sharemind/libconsensusservice.h>
#include <string>
#include <unordered_map>
#include <vector>

struct HostnameAndPort {
    HostnameAndPort(std::string & hostname_, std::uint16_t port_)
        : hostname(hostname_), port(port_)
    { }
    std::string hostname;
    std::uint16_t port;
};

struct __attribute__ ((visibility("internal"))) ModuleData {
    ModuleData(const LogHard::Logger & logger,
        SharemindConsensusFacility * cf);

    const LogHard::Logger logger;
    SharemindConsensusFacility *consensusFacility;
    std::unordered_map<std::string, HostnameAndPort> hostMap;
};

#endif /* SHAREMIND_MOD_KEYDB_MODULEDATA_H */
