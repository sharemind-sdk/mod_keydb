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
#include <set>
#include <sharemind/datastoreapi.h>
#include <sharemind/SyscallsCommon.h>
#include <sharemind/libmodapi/api_0x1.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
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
        const std::string & data)
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
cpp_redis::reply requestAndWait(redis_client & client, Func && fun, Args && ...args) {
        using reply_t = cpp_redis::reply;
        std::promise<reply_t> rep;
        auto future = rep.get_future();
        auto cb = [&rep](reply_t & reply) {
            rep.set_value(reply);
        };
        (client.*fun)(std::forward<Args>(args)..., cb).commit();
        return future.get();
}

bool scanAndClean(SharemindModuleApi0x1SyscallContext * c,
                  const std::string & pattern,
                  std::vector<std::string> & orderedKeys)
{
        auto & client = getClient(c);
        std::set<std::string> keys;
        uint64_t cursor = 0;
        std::string str_cursor = "0";

        using reply_t = cpp_redis::reply;
        std::promise<reply_t> promise;
        auto future = promise.get_future();
        auto cb = [&promise](reply_t & reply) {
            promise.set_value(reply);
        };
        // make the first request
        client.send((std::vector<std::string>)
                {"SCAN", str_cursor, "MATCH", pattern, "COUNT", "3"},
                cb).commit();

        do {
            // get the response
            auto reply = future.get();
            auto & parts = reply.as_array();
            str_cursor = parts[0].as_string();
            std::istringstream iss(str_cursor);
            iss >> cursor;

            if (cursor) {
                // make the next request
                promise = std::promise<reply_t>();
                future = promise.get_future();
                auto cb = [&promise](reply_t & reply) {
                    promise.set_value(reply);
                };
                client.send((std::vector<std::string>)
                        {"SCAN", str_cursor, "MATCH", pattern, "COUNT", "3"},
                        cb).commit();
            }
            // while the next response arrives store the prevoius response into set
            auto & replies = parts[1].as_array();
            for (auto & r : replies) {
                keys.emplace(r.as_string());
            }
        } while (cursor);

        // collect keys from the set into an ordered vector, while at the same time
        // freeing the memory from set
        for (auto it = keys.begin(); it != keys.end(); keys.erase(it++)) {
            orderedKeys.emplace_back(std::move(*it));
        }
        std::vector<std::string> toDelete;
        if (intersection(orderedKeys, toDelete, c)) {
            client.del(toDelete).commit();
            return true;
        }
        return false;
}

} /* namespace { */

SHAREMIND_DEFINE_SYSCALL(keydb_connect, 0, false, 0, 1,
        (void)args;

        auto * store = getDataStore(c, "redis_client");
        auto * client = new redis_client();
        auto deleter = [] (void * p) { delete static_cast<redis_client *>(p); };
        store->set(store, "client", client, deleter);
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

        mod.logger.debug() << "Set with key \"" << key;
        requestAndWait(getClient(c), &redis_client::set, key, value);
    );

SHAREMIND_DEFINE_SYSCALL(keydb_get_size, 1, true, 0, 1,
        (void) args;

        if (crefs->size < 1)
            return SHAREMIND_MODULE_API_0x1_INVALID_CALL;

        const std::string key(static_cast<char const * const>(crefs[0].pData), crefs[0].size - 1u);

        mod.logger.debug() << "keydb_get_size with key \"" << key << '\"';

        auto reply = requestAndWait(getClient(c), &redis_client::get, key);
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

SHAREMIND_DEFINE_SYSCALL(keydb_scan, 0, true, 1, 1,
        (void) args;
        uint64_t * cl_cursor = static_cast<uint64_t *>(refs[0].pData);
        assert(cl_cursor);

        auto * store = getDataStore(c, "keydb_scan");

        std::vector<std::string> * scan = nullptr;
        std::string uid = *cl_cursor ? std::to_string(*cl_cursor) : "1";

        if (!*cl_cursor) { // if a new cursor!
            uint64_t id = 1;
            while (!!store->get(store, uid.c_str())) {
                ++id;
                uid = std::to_string(id);
            }

            assert(crefs[0].size > 0);
            const std::string pattern(static_cast<char const * const>(crefs[0].pData), crefs[0].size-1);
            scan = new std::vector<std::string>();
            auto deleter = [] (void * p) { delete static_cast<std::vector<std::string> *>(p); };
            store->set(store, uid.c_str(), scan, deleter);
            mod.logger.debug() << "keydb_scan: new cursor (" << uid << ')';
            *cl_cursor = id;

            // run consensus because scan on redis does not guarantee order of keys
            scanAndClean(c, pattern, *scan);
        } else { // existing cursor
            scan = static_cast<std::vector<std::string> *>(store->get(store, uid.c_str()));
        }

        assert(scan);

        if (!scan->empty()) {
            return_string(c, returnValue, scan->back());
            scan->pop_back();
        } else {
            *cl_cursor = 0;
            return_string(c, returnValue, std::string("siin ei ole kala"));
            store->remove(store, uid.c_str());
            mod.logger.debug() << "keydb_scan: del cursor (" << uid.c_str() << ')';
        }
    );

SHAREMIND_DEFINE_SYSCALL(keydb_clean, 0, true, 0, 1,
        (void) args;
        mod.logger.debug() << "keydb_clean";
        const std::string pattern(static_cast<char const * const>(crefs[0].pData), crefs[0].size-1);

        std::vector<std::string> orderedKeys;
        bool b = scanAndClean(c, pattern, orderedKeys);
        returnValue->uint64[0] = b ? 1 : 0;
    );
