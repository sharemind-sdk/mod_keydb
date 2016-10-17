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

namespace sharemind {

class __attribute__ ((visibility("internal"))) ModuleData {

public: /* Types: */

    struct HostConfiguration {
        HostConfiguration(const std::string & hostname_,
                const std::uint16_t port_,
                const std::uint16_t scanCount_)
            : hostname(hostname_), port(port_), scanCount(std::to_string(scanCount_))
        { }
        const std::string hostname;
        const std::uint16_t port;
        const std::string scanCount;
    };

    ModuleData(const LogHard::Logger & logger,
        SharemindConsensusFacility * cf);

    bool load(const char * filename, std::string & errorMsg);

    const LogHard::Logger logger;
    SharemindConsensusFacility *consensusFacility;
    std::unordered_map<std::string, HostConfiguration> hostMap;
};

} /* namespace sharemind { */

#endif /* SHAREMIND_MOD_KEYDB_MODULEDATA_H */
