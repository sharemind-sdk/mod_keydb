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


#include <cpp_redis/cpp_redis>
#include <future>
#include <iostream>
#include <LogHard/Logger.h>
#include <sharemind/SyscallsCommon.h>
#include <sharemind/libmodapi/api_0x1.h>
#include <string>
#include <sstream>
#include "ModuleData.h"

#define SHAREMIND_DEFINE_SYSCALL(name,nargs,rv,nrefs,ncrefs,code) \
    SHAREMIND_EXTERN_C_BEGIN \
    SHAREMIND_MODULE_API_0x1_SYSCALL(name, args, num_args, refs, crefs, \
                                     returnValue, c) \
    { \
        if (!SyscallArgs<nargs,rv,nrefs,ncrefs>::check(num_args, refs, crefs, returnValue)) \
            return SHAREMIND_MODULE_API_0x1_INVALID_CALL; \
        try { \
            code \
            return SHAREMIND_MODULE_API_0x1_OK; \
        } catch (...) { \
            return sharemind::catchModuleApiErrors(); \
        } \
    } \
    SHAREMIND_EXTERN_C_END


using namespace sharemind;
cpp_redis::redis_client client;

void reply_to_stream(const cpp_redis::reply & reply, std::ostringstream & stream) {
    if (reply.is_null()) {
        stream << "(nil)";
    }
    else if (reply.is_string() || reply.is_error()) {
        stream << reply.as_string();
    } else if (reply.is_integer()) {
        stream << reply.as_integer();
    } else if (reply.is_array()) {
        stream << '[';
        for (const auto & rep : reply.as_array()) {
            reply_to_stream(rep, stream);
            stream << ", ";
        }
        stream << ']';
    }
}

void callback_debug(const cpp_redis::reply & reply, const LogHard::Logger & logger) {
    std::ostringstream stream;
    reply_to_stream(reply, stream);
    logger.debug() << "Received a new reply: " << stream.str();
}

SHAREMIND_DEFINE_SYSCALL(keydb_connect, 0, false, 0, 0,
        (void)args;

        const auto & mod = *static_cast<const ModuleData * const>(c->moduleHandle);
        try {
            client.connect(mod.host, mod.port);
        } catch (cpp_redis::redis_error & er) {
            mod.logger.error() << er.what();
            throw;
        }
    );

SHAREMIND_DEFINE_SYSCALL(keydb_disconnect, 0, false, 0, 0,
        (void)args;

        const auto & mod = *static_cast<const ModuleData * const>(c->moduleHandle);
        (void) mod;

        client.sync_commit();
        client.disconnect();
    );

SHAREMIND_DEFINE_SYSCALL(keydb_set, 0, false, 0, 2,
        (void) args;

        if (crefs->size < 1)
            return SHAREMIND_MODULE_API_0x1_INVALID_CALL;

        const auto & mod = *static_cast<const ModuleData * const>(c->moduleHandle);

        const std::string key(static_cast<char const * const>(crefs[0].pData), crefs[0].size - 1);
        const std::string value(static_cast<char const * const>(crefs[1].pData), crefs[1].size - 1);

        mod.logger.info() << "Set with key \"" << key << "\" and value \"" << value << '\"';

        auto cb = std::bind(callback_debug, std::placeholders::_1, mod.logger);

        client.set(key, value, cb).commit();
    );

SHAREMIND_DEFINE_SYSCALL(keydb_get_size, 0, true, 1, 1,
        (void) args;

        if (crefs->size < 1)
            return SHAREMIND_MODULE_API_0x1_INVALID_CALL;

        const auto & mod = *static_cast<const ModuleData * const>(c->moduleHandle);
        const std::string key(static_cast<char const * const>(crefs[0].pData), crefs[0].size - 1u);

        mod.logger.debug() << "keydb_get_size with key \"" << key << '\"';

        std::promise<cpp_redis::reply> rep;
        auto fut = rep.get_future();
        auto cb = [&rep](cpp_redis::reply & reply) {
            rep.set_value(reply);
        };

        client.get({key}, cb).commit();
        auto reply = fut.get();
        callback_debug(reply, mod.logger);
        const std::string & data = reply.as_string();

        // store returned data in heap
        std::string *heapString = new std::string(data);
        assert(refs[0].size == sizeof(heapString));
        // store pointer to heap in the secrec variable
        memcpy(refs[0].pData, &heapString, refs[0].size);
        // return size of data
        returnValue->uint64[0] = data.size();
    );

SHAREMIND_DEFINE_SYSCALL(keydb_get, 0, false, 1, 1,
        (void) args;

        const auto & mod = *static_cast<const ModuleData * const>(c->moduleHandle);
        const std::string * data;
        // pointer to data in heap was saved before
        assert(crefs[0].size == sizeof(data));
        // get pointer from secrec
        memcpy(&data, crefs[0].pData, sizeof(data));
        mod.logger.debug() << "keydb_get";

        assert(data);
        // copy data to secrec
        memcpy(refs[0].pData, data->data(), data->size());
        // free data from heap
        delete data;
    );

SHAREMIND_DEFINE_SYSCALL(keydb_del, 0, false, 0, 1,
        (void) args;

        const std::string key(static_cast<char const * const>(crefs[0].pData), crefs[0].size - 1u);
        const auto & mod = *static_cast<const ModuleData * const>(c->moduleHandle);
        (void) mod;
        client.del({key}).commit();
    );

SHAREMIND_DEFINE_SYSCALL(keydb_scan,0,true,0,1,
        (void) args;
        const auto & mod = *static_cast<const ModuleData * const>(c->moduleHandle);
        (void) mod;
    );

void return_string(SharemindModuleApi0x1SyscallContext * c, SharemindCodeBlock * returnValue)
{
        const std::string data = "sadasd";
        const uint64_t mem_hndl = c->publicAlloc(c, data.size());
        if (mem_hndl) {
            void * const ptr = c->publicMemPtrData(c, mem_hndl);
            memcpy(ptr, data.c_str(), data.size());
            returnValue->p[0] = ptr;
        }
        returnValue->uint64[0] = mem_hndl;
        returnValue[0].uint64[0] = false;
}
