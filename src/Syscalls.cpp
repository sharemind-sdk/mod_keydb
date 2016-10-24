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


#include <algorithm>
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

#define SHAREMIND_DEFINE_SYSCALL(name,nargs,rv,nrefs,ncrefs,code) \
    SHAREMIND_EXTERN_C_BEGIN \
    SHAREMIND_MODULE_API_0x1_SYSCALL(name, args, num_args, refs, crefs, \
                                     returnValue, c) \
    { \
        if (!sharemind::SyscallArgs<nargs,rv,nrefs,ncrefs>::check(num_args, refs, crefs, returnValue)) \
            return SHAREMIND_MODULE_API_0x1_INVALID_CALL; \
        assert(c->moduleHandle); \
        auto & mod = *static_cast<sharemind::ModuleData * const>(c->moduleHandle); \
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

// names used for specific datastore namespaces
constexpr std::array<const char *, 3> dataStores{{"keydb", "keydb_get", "keydb_scan"}};
enum DataStoreNamespace {
    NS_KEYDB = 0,
    NS_GET = 1,
    NS_SCAN = 2,
    NS_MAX = NS_SCAN
};
static_assert(dataStores.size() == NS_MAX + 1, "DataStoreNamespace enum and dataStores array must be in sync!");

inline void returnString(SharemindModuleApi0x1SyscallContext * c,
        SharemindCodeBlock * returnValue,
        const std::string & data)
{
    const uint64_t mem_hndl = c->publicAlloc(c, data.size() + 1);
    if (mem_hndl) {
        char * const ptr = static_cast<char * const>(c->publicMemPtrData(c, mem_hndl));
        memcpy(ptr, data.c_str(), data.size());
        // add the zero byte at the end
        *(ptr + data.size()) = '\0';
    }
    returnValue->uint64[0] = mem_hndl;
}

inline SharemindDataStoreFactory * getDataStoreFactory(SharemindModuleApi0x1SyscallContext * c) {
    auto * const factory =
        static_cast<SharemindDataStoreFactory * const>(
                c->processFacility(c, "DataStoreFactory"));
    if (!factory)
        throw std::logic_error(
                "DataStoreFactory is missing!");
    return factory;
}

inline SharemindDataStore * getDataStore(SharemindModuleApi0x1SyscallContext * c, DataStoreNamespace ns) {
    auto * factory = getDataStoreFactory(c);
    return factory->get_datastore(factory, dataStores[ns]);
}

template <typename T>
inline T & getItem(SharemindModuleApi0x1SyscallContext * c, const char * name) {
    auto * store = getDataStore(c, NS_KEYDB);
    T * item = static_cast<T *>(store->get(store, name));
    if (!item) {
        throw std::logic_error(
                "Cannot get some process instance specific data. Make sure to call keydb_connect!");
    }
    return *item;
}

inline cpp_redis::redis_client & getClient(SharemindModuleApi0x1SyscallContext * c) {
    return getItem<cpp_redis::redis_client>(c, "Client");
}

inline sharemind::ModuleData::HostConfiguration & getHostConf(SharemindModuleApi0x1SyscallContext * c) {
    return getItem<sharemind::ModuleData::HostConfiguration>(c, "HostConfiguration");
}

template<typename Func, typename... Args>
cpp_redis::reply requestAndWait(cpp_redis::redis_client & client, Func && fun, Args && ...args) {
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
                  std::vector<std::string> & orderedKeys,
                  bool cleanUpOrderedKeys = false)
{
    auto & client = getClient(c);
    auto & hostconf = getHostConf(c);

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
            {"SCAN", str_cursor, "MATCH", pattern, "COUNT", hostconf.scanCount},
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
                    {"SCAN", str_cursor, "MATCH", pattern, "COUNT", hostconf.scanCount},
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
    if (sharemind::intersection(orderedKeys, toDelete, c)) {
        if (!toDelete.empty()) {
            client.del(toDelete).commit();
        }
        if (cleanUpOrderedKeys) {
            for (auto & k : toDelete) {
                auto it = std::lower_bound(orderedKeys.begin(), orderedKeys.end(), k);
                orderedKeys.erase(it);
            }
        }
        return true;
    }
    return false;
}

} /* namespace { */

SHAREMIND_DEFINE_SYSCALL(keydb_connect, 0, false, 0, 1,
        (void)args;

        if (crefs[0].size < 1)
            return SHAREMIND_MODULE_API_0x1_INVALID_CALL;

        const std::string key(static_cast<char const * const>(crefs[0].pData), crefs[0].size - 1);
        auto it = mod.hostMap.find(key);
        if (it == mod.hostMap.end()) {
            mod.logger.error() << "Could not find the host \"" << key
                << "\" in the module hosts configuration.";
            return SHAREMIND_MODULE_API_0x1_INVALID_CALL;
        }
        auto & hc = it->second;

        auto * store = getDataStore(c, NS_KEYDB);
        auto * client = new cpp_redis::redis_client();
        auto deleter = [] (void * p) { delete static_cast<cpp_redis::redis_client *>(p); };

        store->set(store, "Client", client, deleter);
        store->set(store, "HostConfiguration", &hc, nullptr);

        client->connect(hc.hostname, hc.port);
    );

SHAREMIND_DEFINE_SYSCALL(keydb_disconnect, 0, false, 0, 0,
        (void)args;

        auto & client = getClient(c);
        client.sync_commit();
        client.disconnect();

        auto * factory = getDataStoreFactory(c);
        for (auto ns : dataStores) {
            auto * store = factory->get_datastore(factory, ns);
            store->clear(store);
        }
    );

SHAREMIND_DEFINE_SYSCALL(keydb_set, 1, false, 0, 2,
        if (args[0].uint64[0] > 1)
            return SHAREMIND_MODULE_API_0x1_INVALID_CALL;
        if (crefs->size < 1)
            return SHAREMIND_MODULE_API_0x1_INVALID_CALL;

        bool isArray = args[0].uint64[0];

        if (isArray && crefs[1].size < 1)
            return SHAREMIND_MODULE_API_0x1_INVALID_CALL;

        const std::string key(static_cast<char const * const>(crefs[0].pData), crefs[0].size - 1);
        // arrays need size -1, scalars do not need it
        const std::string value(static_cast<char const * const>(crefs[1].pData), crefs[1].size - isArray);

        mod.logger.debug() << "Set with key \"" << key << "\" size = " << (int)value.size();
        std::vector<std::string> command;
        command.reserve(4);
        command.emplace_back("SET");
        command.emplace_back(key);
        command.emplace_back(value);
        if (getHostConf(c).disableOverwrite)
            command.emplace_back("NX");
        auto cb = [&mod] (cpp_redis::reply & r) {
            if ( r.is_error()) {
                mod.logger.error() << r.as_string();
            }
        };
        getClient(c).send(command, cb).commit();
    );

SHAREMIND_DEFINE_SYSCALL(keydb_get_size, 1, true, 0, 1,
        (void) args;

        if (crefs->size < 1)
            return SHAREMIND_MODULE_API_0x1_INVALID_CALL;

        const std::string key(static_cast<char const * const>(crefs[0].pData), crefs[0].size - 1);

        mod.logger.debug() << "keydb_get_size with key \"" << key << '\"';

        auto reply = requestAndWait(getClient(c), &cpp_redis::redis_client::get, key);
        const std::string & data = reply.as_string();

        // store returned data in heap
        std::string *heapString = new std::string(data);

        auto * store = getDataStore(c, NS_GET);

        uint64_t id = 0;
        std::string id_str;
        do {
            id_str = std::to_string(id);
            ++id;
        } while (!!store->get(store, id_str.c_str()));

        auto deleter = [](void * p) { delete static_cast<std::string *>(p); };
        store->set(store, id_str.c_str(), heapString, deleter);

        args[0].uint64[0] = id - 1;

        // return size of data
        returnValue->uint64[0] = data.size();
    );

SHAREMIND_DEFINE_SYSCALL(keydb_get, 1, false, 1, 0,
        mod.logger.debug() << "keydb_get";

        auto * store = getDataStore(c, NS_GET);

        std::string name = std::to_string(args[0].uint64[0]);
        auto * data = static_cast<std::string *>(store->get(store, name.c_str()));
        if (!data)
            throw std::logic_error(
                    "Cannot get instance of data, was keydb_get_size called before?");

        mod.logger.debug() << "reference size, data size: "
            << (int) refs[0].size << ", " << (int) data->size();

        assert(refs[0].size == data->size() || refs[0].size == data->size()+1);
        // copy data to secrec
        memcpy(refs[0].pData, data->data(), data->size());

        // free data from heap
        store->remove(store, name.c_str());
    );

SHAREMIND_DEFINE_SYSCALL(keydb_del, 0, false, 0, 1,
        (void) args;

        if (crefs[0].size < 1)
            return SHAREMIND_MODULE_API_0x1_INVALID_CALL;

        const std::string key(static_cast<char const * const>(crefs[0].pData), crefs[0].size - 1);
        getClient(c).del({key}).commit();
    );

SHAREMIND_DEFINE_SYSCALL(keydb_scan, 0, true, 1, 1,
        (void) args;
        uint64_t * cl_cursor = static_cast<uint64_t *>(refs[0].pData);
        assert(cl_cursor);

        auto * store = getDataStore(c, NS_SCAN);

        std::vector<std::string> * scan = nullptr;
        std::string uid = *cl_cursor ? std::to_string(*cl_cursor) : "1";

        if (!*cl_cursor) { // if a new cursor!
            uint64_t id = 1;
            while (!!store->get(store, uid.c_str())) {
                ++id;
                uid = std::to_string(id);
            }

            if (crefs[0].size < 1)
                return SHAREMIND_MODULE_API_0x1_INVALID_CALL;

            const std::string pattern(static_cast<char const * const>(crefs[0].pData), crefs[0].size-1);
            scan = new std::vector<std::string>();
            auto deleter = [] (void * p) { delete static_cast<std::vector<std::string> *>(p); };
            store->set(store, uid.c_str(), scan, deleter);
            mod.logger.debug() << "keydb_scan: new cursor (" << uid << ')';
            *cl_cursor = id;

            // run consensus because scan on redis does not guarantee order of keys
            scanAndClean(c, pattern, *scan, true);
        } else { // existing cursor
            scan = static_cast<std::vector<std::string> *>(store->get(store, uid.c_str()));
        }

        assert(scan);

        if (!scan->empty()) {
            returnString(c, returnValue, scan->back());
            scan->pop_back();
        } else {
            *cl_cursor = 0;
            // need to return something
            returnString(c, returnValue, std::string(""));
            store->remove(store, uid.c_str());
            mod.logger.debug() << "keydb_scan: del cursor (" << uid.c_str() << ')';
        }
    );

SHAREMIND_DEFINE_SYSCALL(keydb_clean, 0, true, 0, 1,
        (void) args;
        mod.logger.debug() << "keydb_clean";

        if (crefs[0].size < 1)
            return SHAREMIND_MODULE_API_0x1_INVALID_CALL;

        const std::string pattern(static_cast<char const * const>(crefs[0].pData), crefs[0].size-1);

        std::vector<std::string> orderedKeys;
        bool b = scanAndClean(c, pattern, orderedKeys);
        returnValue->uint64[0] = b ? 1 : 0;
    );
