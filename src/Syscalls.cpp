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
#include <set>
#include <sharemind/datastoreapi.h>
#include <sharemind/SyscallsCommon.h>
#include <sharemind/libmodapi/api_0x1.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include "Intersection.h"
#include "ModuleData.h"

using namespace cpp_redis;

#define SHAREMIND_DEFINE_SYSCALL(name,nargs,rv,nrefs,ncrefs,code) \
    SHAREMIND_EXTERN_C_BEGIN \
    SHAREMIND_MODULE_API_0x1_SYSCALL(name, args, num_args, refs, crefs, \
                                     returnValue, c) \
    { \
        if (!sharemind::SyscallArgs<nargs,rv,nrefs,ncrefs>::check(num_args, refs, crefs, returnValue)) \
            return SHAREMIND_MODULE_API_0x1_INVALID_CALL; \
        assert(c->moduleHandle); \
        auto & mod = *static_cast<ModuleData * const>(c->moduleHandle); \
        try { \
            code \
            return SHAREMIND_MODULE_API_0x1_OK; \
        } catch (std::exception & exception) { \
            mod.logger.error() << exception.what(); \
            mod.logger.error() << "in " #name; \
            return sharemind::catchModuleApiErrors(); \
        } catch (...) { \
            mod.logger.error() << "Error in " #name ; \
            return sharemind::catchModuleApiErrors(); \
        } \
    } \
    SHAREMIND_EXTERN_C_END

namespace {

inline void return_string(SharemindModuleApi0x1SyscallContext * c,
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
        assert(factory && "DataStoreFactory facility is missing!");

        return factory->get_datastore(factory, ns);
}

inline redis_client & getClient(SharemindModuleApi0x1SyscallContext * c) {
        auto * store = getDataStore(c, "redis_client");
        auto * client = static_cast<redis_client *>(store->get(store, "client"));
        if (!client) {
            throw std::logic_error(
                    "Cannot get instance of redis_client. Make sure to call keydb_connect!");
        }
        return *client;
}

template<typename Func, typename... Args>
cpp_redis::reply makeRequest(redis_client & client, Func && fun, Args && ...args) {
        std::promise<cpp_redis::reply> rep;
        auto fut = rep.get_future();
        auto cb = [&rep](cpp_redis::reply & reply) {
            rep.set_value(reply);
        };
        (client.*fun)(std::forward<Args>(args)..., cb).commit();
        auto reply = fut.get();
        return reply;
}

} /* namespace { */

SHAREMIND_DEFINE_SYSCALL(keydb_connect, 0, false, 0, 1,
        (void)args;

        auto * store = getDataStore(c, "redis_client");
        auto * client = new redis_client();
        store->set(store, "client", client, [] (void * p) { delete static_cast<redis_client *>(p); } );
        const std::string key(static_cast<char const * const>(crefs[0].pData), crefs[0].size - 1);
        auto it = mod.hostMap.find(key);
        if (it == mod.hostMap.end()) {
            mod.logger.error() << "Could not find the host \"" << key
                << "\" in the module hosts configuration.";
            return SHAREMIND_MODULE_API_0x1_INVALID_MODULE_CONFIGURATION;
        }
        auto & hp = it->second;
        client->connect(hp.hostname, hp.port);
    );

SHAREMIND_DEFINE_SYSCALL(keydb_disconnect, 0, false, 0, 0,
        (void)args;
        auto & client = getClient(c);
        client.sync_commit();
        client.disconnect();
    );

SHAREMIND_DEFINE_SYSCALL(keydb_set, 0, false, 0, 2,
        (void) args;

        if (crefs->size < 1)
            return SHAREMIND_MODULE_API_0x1_INVALID_CALL;

        const std::string key(static_cast<char const * const>(crefs[0].pData), crefs[0].size - 1);
        const std::string value(static_cast<char const * const>(crefs[1].pData), crefs[1].size - 1);

        mod.logger.debug() << "Set with key \"" << key << "\" and value \"" << value << '\"';
        makeRequest(getClient(c), &redis_client::set, key, value);
    );

SHAREMIND_DEFINE_SYSCALL(keydb_get_size, 1, true, 0, 1,
        (void) args;

        if (crefs->size < 1)
            return SHAREMIND_MODULE_API_0x1_INVALID_CALL;

        const std::string key(static_cast<char const * const>(crefs[0].pData), crefs[0].size - 1u);

        mod.logger.debug() << "keydb_get_size with key \"" << key << '\"';

        auto reply = makeRequest(getClient(c), &redis_client::get, key);
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
        getClient(c).del({key}).commit();
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

            std::string str_cursor = std::to_string(scan->cursor);
            mod.logger.debug() << "scan with " << str_cursor;

            auto reply = makeRequest(getClient(c), &redis_client::send,
                    (std::vector<std::string>){"SCAN", str_cursor, "MATCH", scan->pattern, "COUNT", "3"});

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

SHAREMIND_DEFINE_SYSCALL(keydb_intersection, 0, true, 0, 0,
        (void) args;
        mod.logger.debug() << "keydb_intersection";
        auto & client = getClient(c);

        std::set<std::string> keys;
        uint64_t cursor = 0;
        std::string str_cursor = "0";
        do {
            auto reply = makeRequest(getClient(c), &redis_client::send,
                    (std::vector<std::string>){"SCAN", str_cursor, "MATCH", "*", "COUNT", "3"});
            auto & parts = reply.as_array();
            str_cursor = parts[0].as_string();
            std::istringstream iss(str_cursor);
            iss >> cursor;

            auto & replies = parts[1].as_array();
            for (auto & r : replies) {
                keys.emplace(r.as_string());
            }
        } while (cursor != 0);

        std::vector<std::string> orderedKeys;
        for (auto it = keys.begin(); it != keys.end(); ++it) {
            orderedKeys.emplace_back(*it);
            keys.erase(it);
        }
        mod.logger.debug() << "Keys: ";
        for (auto & s : orderedKeys) {
            mod.logger.debug() << s;
        }
        mod.logger.debug() << "end";

        std::vector<std::string> toBeDeleted;
        if (intersection(orderedKeys, toBeDeleted, c)) {
            mod.logger.debug() << "keys to delete: " << toBeDeleted.size();
            client.del(toBeDeleted).sync_commit();
            returnValue->uint64[0] = 1;
        } else {
            returnValue->uint64[0] = 0;
        }
        // TODO: maybe should do some other consensus here
        // for example to make sure all servers are in the same spot
    );
