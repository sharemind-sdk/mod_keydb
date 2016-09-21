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
#include <deque>
#include <future>
#include <iostream>
#include <LogHard/Logger.h>
#include <sharemind/datastoreapi.h>
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

void return_string(SharemindModuleApi0x1SyscallContext * c,
        SharemindCodeBlock * returnValue,
        std::string & data)
{
        const uint64_t mem_hndl = c->publicAlloc(c, data.size());
        if (mem_hndl) {
            void * const ptr = c->publicMemPtrData(c, mem_hndl);
            memcpy(ptr, data.c_str(), data.size());
        }
        returnValue->uint64[0] = mem_hndl;
}

inline SharemindDataStore * getDataStore(SharemindModuleApi0x1SyscallContext * c, const char * ns) {
        auto * const factory =
            static_cast<SharemindDataStoreFactory * const>(
                    c->processFacility(c, "DataStoreFactory"));

        return factory->get_datastore(factory, ns);
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

        mod.logger.debug() << "Set with key \"" << key << "\" and value \"" << value << '\"';

        auto cb = std::bind(callback_debug, std::placeholders::_1, mod.logger);

        client.set(key, value, cb).commit();
    );

SHAREMIND_DEFINE_SYSCALL(keydb_get_size, 1, true, 0, 1,
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

        auto * store = getDataStore(c, "keydb_get");

        uint64_t id = 0;
        std::string id_str;
        do {
            id_str = std::to_string(id);
            ++id;
        } while (!!store->get(store, id_str.c_str()));

        auto deleter = [](void * p) { delete static_cast<std::string *>(p); };
        store->set(store, id_str.c_str(), heapString, deleter);

        args[0].uint64[0] = id - 1;
        mod.logger.debug() << "keydb_get_size " << args[0].uint64[0] << " " << id_str;

        // return size of data
        returnValue->uint64[0] = data.size();
    );

SHAREMIND_DEFINE_SYSCALL(keydb_get, 1, false, 1, 0,
        const auto & mod = *static_cast<const ModuleData * const>(c->moduleHandle);
        mod.logger.debug() << "keydb_get";

        auto * store = getDataStore(c, "keydb_get");

        std::string name = std::to_string(args[0].uint64[0]);
        auto * data = static_cast<std::string *>(store->get(store, name.c_str()));

        assert(data);
        // copy data to secrec
        memcpy(refs[0].pData, data->data(), data->size());

        // free data from heap
        store->remove(store, name.c_str());
    );

SHAREMIND_DEFINE_SYSCALL(keydb_del, 0, false, 0, 1,
        (void) args;

        const std::string key(static_cast<char const * const>(crefs[0].pData), crefs[0].size - 1u);
        const auto & mod = *static_cast<const ModuleData * const>(c->moduleHandle);
        (void) mod;
        client.del({key}).commit();
    );

struct scan_struct {
    scan_struct(const std::string & pattern)
        : pattern{pattern}, cursor{0}
    { }

    const std::string pattern;
    std::deque<std::string> que;
    uint64_t cursor;
};

SHAREMIND_DEFINE_SYSCALL(keydb_scan, 0, true, 1, 1,
        (void) args;
        const auto & mod = *static_cast<const ModuleData * const>(c->moduleHandle);
        mod.logger.debug() << "keydb_scan";

        uint64_t * cl_cursor = static_cast<uint64_t *>(refs[0].pData);
        assert(cl_cursor);

        auto * store = getDataStore(c, "keydb_scan");

        scan_struct * scan = nullptr;
        std::string client_cursor;
        const char * uid = nullptr;

        bool should_scan = true;

        if (!*cl_cursor) {
            uint64_t id = 1;
            do {
                client_cursor = std::to_string(id);
                ++id;
            } while (!!store->get(store, client_cursor.c_str()));

            assert(crefs[0].size > 0);
            const std::string pattern(static_cast<char const * const>(crefs[0].pData), crefs[0].size-1);
            scan = new scan_struct(pattern);
            auto deleter = [] (void * p) { delete static_cast<scan_struct *>(p); };
            uid = client_cursor.c_str();
            store->set(store, uid, scan, deleter);
            mod.logger.debug() << "keydb_scan : new cursor (" << uid << ')';
            *cl_cursor = --id;
        } else {
            client_cursor = std::to_string(*cl_cursor);
            uid = client_cursor.c_str();
            scan = static_cast<scan_struct *>(store->get(store, uid));
            mod.logger.debug() << "keydb_scan : old cursor (" << uid << ')';
            should_scan = scan->cursor != 0;
        }

        assert(scan);
        while (scan->que.empty() && should_scan) {
            mod.logger.debug() << "keydb_scan : scan";
            std::promise<cpp_redis::reply> rep;
            auto fut = rep.get_future();
            auto cb = [&rep](cpp_redis::reply & reply) {
                rep.set_value(reply);
            };

            std::string str_cursor = std::to_string(scan->cursor);
            mod.logger.debug() << "scan with " << str_cursor;
            client.send({"SCAN", str_cursor, "MATCH", scan->pattern, "COUNT", "3"}, cb).commit();

            auto reply = fut.get();
            callback_debug(reply, mod.logger);

            auto & parts = reply.as_array();
            assert(parts.size() == 2);
            std::istringstream iss(parts[0].as_string());
            uint64_t new_cursor;
            iss >> new_cursor;

            // add returned entities to scan_cursor
            if (!parts[1].is_null()) {
                auto & items = parts[1].as_array();
                for (auto & item : items) {
                    scan->que.push_back(item.as_string());
                }
            }

            scan->cursor = new_cursor;
            mod.logger.debug() << "new cursor " << new_cursor;

            if (!new_cursor) {
                break;
            }
        }

        if (!scan->que.empty()) {
            mod.logger.debug() << "keydb_scan : return string : " << scan->que.front();
            return_string(c, returnValue, scan->que.front());
            scan->que.pop_front();
        }
        else if (!should_scan) {
            *cl_cursor = 0;
            store->remove(store, uid);
            mod.logger.debug() << "keydb_scan : del cursor (" << uid << ')';
        }
    );
