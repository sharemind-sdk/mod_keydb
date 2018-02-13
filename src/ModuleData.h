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

#ifndef SHAREMIND_MOD_KEYDB_MODULEDATA_H
#define SHAREMIND_MOD_KEYDB_MODULEDATA_H

#include <cstdint>
#include <LogHard/Logger.h>
#include <sharemind/libconsensusservice.h>
#include <sharemind/SimpleUnorderedStringMap.h>
#include <string>
#include <vector>

namespace sharemind {

class __attribute__ ((visibility("internal"))) ModuleData {

public: /* Types: */

    struct HostConfiguration {
        HostConfiguration(const std::string & hostname_,
                const std::uint16_t port_,
                const std::uint16_t scanCount_,
                const bool disableOverwrite_)
            : hostname(hostname_)
            , port(port_)
            , scanCount(std::to_string(scanCount_))
            , disableOverwrite(disableOverwrite_)
        { }
        const std::string hostname;
        const std::uint16_t port;
        const std::string scanCount;
        const bool disableOverwrite;
    };

    ModuleData(const LogHard::Logger & logger,
        SharemindConsensusFacility * cf);

    bool load(const char * filename, std::string & errorMsg);

    const LogHard::Logger logger;
    SharemindConsensusFacility *consensusFacility;
    SimpleUnorderedStringMap<HostConfiguration> hostMap;
};

} /* namespace sharemind { */

#endif /* SHAREMIND_MOD_KEYDB_MODULEDATA_H */
