/*
 * Copyright (C) Cybernetica
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
#include <exception>
#include <future>
#include <hiredis/hiredis.h>
#include <iostream>
#include <LogHard/Logger.h>
#include <memory>
#include <set>
#include <sharemind/datastoreapi.h>
#include <sharemind/module-apis/api_0x1.h>
#include <sharemind/SyscallsCommon.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>
#include "Intersection.h"
#include "ModuleData.h"


#define SHAREMIND_DEFINE_SYSCALL(name,nargs,rv,nrefs,ncrefs,...) \
    SHAREMIND_EXTERN_C_BEGIN \
    SHAREMIND_MODULE_API_0x1_SYSCALL(name, args, num_args, refs, crefs, \
                                     returnValue, c) \
    { \
        if (!sharemind::SyscallArgs<nargs,rv,nrefs,ncrefs>::check(num_args, refs, crefs, returnValue)) \
            return SHAREMIND_MODULE_API_0x1_INVALID_CALL; \
        assert(c->moduleHandle); \
        auto & mod = *static_cast<sharemind::ModuleData * const>(c->moduleHandle); \
        try { \
            __VA_ARGS__ \
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

class SynchronousRedisClient {

public: /* Types: */

    class Exception: public std::exception {};
    class HiredisError final: public Exception {

    public: /* Methods: */

        HiredisError(::redisContext const & context)
            : m_errorString(std::string("Hiredis error: ") + context.errstr)
        {}

        char const * what() const noexcept final override
        { return m_errorString.c_str(); }

    private: /* Fields: */

        std::string const m_errorString;

    };

    class ConversionError final: public Exception {

    public: /* Methods: */

        ConversionError(char const * const staticStr)
            : m_errorString(staticStr)
        {}

        char const * what() const noexcept final override
        { return m_errorString; }

    private: /* Fields: */

        char const * const m_errorString;

    };

    class Reply {

        friend class SynchronousRedisClient;

    private: /* Types: */

        using ReplyPtr =
                std::unique_ptr<::redisReply, void (*)(::redisReply * const)>;

    public: /* Methods: */

        Reply(Reply &&) noexcept = default;
        Reply & operator =(Reply &&) noexcept = default;

        bool isError() const noexcept
        { return m_reply && (m_reply->type == REDIS_REPLY_ERROR); }

        std::string asString() const {
            assert(m_reply);
            if (m_reply->type != REDIS_REPLY_STRING)
                throw ConversionError("Redis reply was not a string!");
            return getString();
        }

        std::vector<Reply> asArray() const {
            assert(m_reply);
            if (m_reply->type != REDIS_REPLY_ARRAY)
                throw ConversionError("Redis reply was not an array!");
            std::vector<Reply> r;
            auto const numElements(m_reply->elements);
            r.reserve(numElements);
            for (std::size_t  i = 0u; i < numElements; ++i)
                r.emplace_back(Reply(m_reply->element[i], nullptr));
            return r;
        }

        std::string errorString() const {
            assert(m_reply);
            if (m_reply->type != REDIS_REPLY_ERROR)
                throw ConversionError("Redis reply was not a string!");
            return getString();
        }

    private: /* Methods: */

        std::string getString() const {
            assert(m_reply);
            using U =
                    std::make_unsigned<
                        std::decay<decltype(m_reply->len)>::type
                    >::type;
            return std::string(m_reply->str, static_cast<U>(m_reply->len));
        }

        static void doFree(::redisReply * const r) noexcept
        { ::freeReplyObject(r); }

        static void noFree(::redisReply * const) noexcept {}

        Reply(::redisReply * const reply)
            : m_reply(reply, &Reply::doFree)
        {}

        Reply(::redisReply * const reply, decltype(nullptr) const)
            : m_reply(reply, &Reply::noFree)
        {}

    private: /* Fields: */

        ReplyPtr m_reply;

    };

private: /* Types: */

    struct HiredisContextDeleter {
        void operator()(::redisContext * const p) const noexcept
        { ::redisFree(p); }
    };

    using ContextPtr = std::unique_ptr<::redisContext, HiredisContextDeleter>;

public: /* Methods: */

    void connect(std::string const & hostname, std::uint16_t port) {
        assert(!m_redisContext);
        ContextPtr context(::redisConnect(hostname.c_str(), port));
        if (!context)
            throw std::bad_alloc();
        if (context->err)
            throw HiredisError(*context);
        m_redisContext = std::move(context);
    }

    void disconnect() noexcept { m_redisContext.reset(); }

    template <typename ... Args>
    Reply command(Args && ... args) {
        if (auto * reply = ::redisCommand(m_redisContext.get(),
                                          std::forward<Args>(args)...))
            return static_cast<::redisReply *>(reply);
        throw HiredisError(*m_redisContext);
    }

private: /* Fields: */

    ContextPtr m_redisContext;

};

inline SynchronousRedisClient & getClient(SharemindModuleApi0x1SyscallContext * c) {
    return getItem<SynchronousRedisClient>(c, "Client");
}

inline sharemind::ModuleData::HostConfiguration & getHostConf(SharemindModuleApi0x1SyscallContext * c) {
    return getItem<sharemind::ModuleData::HostConfiguration>(c, "HostConfiguration");
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

    // make the first request
    auto reply(client.command("SCAN %s MATCH %s COUNT %s",
                              str_cursor.c_str(),
                              pattern.c_str(),
                              hostconf.scanCount.c_str()));
    do {
        // get the response
        auto const parts(reply.asArray());
        str_cursor = parts[0].asString();

        std::istringstream iss(str_cursor);
        iss >> cursor;

        if (cursor) {
            // make the next request
            reply = client.command("SCAN %s MATCH %s COUNT %s",
                                   str_cursor.c_str(),
                                   pattern.c_str(),
                                   hostconf.scanCount.c_str());
        }
        // while the next response arrives store the prevoius response into set
        auto const replies(parts[1].asArray());
        for (auto & r : replies)
            keys.emplace(r.asString());
    } while (cursor);

    // collect keys from the set into an ordered vector, while at the same time
    // freeing the memory from set
    for (auto it = keys.begin(); it != keys.end(); keys.erase(it++)) {
        orderedKeys.emplace_back(std::move(*it));
    }
    std::vector<std::string> toDelete;
    if (sharemind::intersection(orderedKeys, toDelete, c)) {
        if (!toDelete.empty()) {
            std::ostringstream oss;
            oss << "DEL";
            for (auto const & key : toDelete)
                oss << ' ' << key;
            client.command(oss.str().c_str());
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

        auto * store = getDataStore(c, NS_KEYDB);

        if (store->get(store, "Client")) {
            mod.logger.error() << "You have already called keydb_connect!\n"
                               << "First call keydb_disconnect to drop the old connection.";
            return SHAREMIND_MODULE_API_0x1_INVALID_CALL;
        }

        const std::string key(static_cast<char const * const>(crefs[0].pData), crefs[0].size - 1);
        auto it = mod.hostMap.find(key);
        if (it == mod.hostMap.end()) {
            mod.logger.error() << "Could not find the host \"" << key
                << "\" in the module hosts configuration.";
            return SHAREMIND_MODULE_API_0x1_INVALID_CALL;
        }
        auto & hc = it->second;

        auto * client = new SynchronousRedisClient;
        auto deleter =
                [](void * const p) noexcept
                { delete static_cast<SynchronousRedisClient *>(p); };

        store->set(store, "Client", client, deleter);
        store->set(store, "HostConfiguration", &hc, nullptr);

        client->connect(hc.hostname, hc.port);
    );

SHAREMIND_DEFINE_SYSCALL(keydb_disconnect, 0, false, 0, 0,
        (void)args;

        getClient(c).disconnect();

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

        mod.logger.debug() << "Set with key \"" << key << "\" size = "
                           << value.size();

        auto const reply(getClient(c).command(
                             getHostConf(c).disableOverwrite
                             ? "SET %b %b NX"
                             : "SET %b %b",
                             static_cast<char const * const>(crefs[0].pData),
                             crefs[0].size - 1,
                             static_cast<char const * const>(crefs[1].pData),
                             crefs[1].size - isArray
                             ));
        if (reply.isError())
            mod.logger.error() << reply.errorString();
    );

SHAREMIND_DEFINE_SYSCALL(keydb_get_size, 1, true, 0, 1,
        (void) args;

        if (crefs->size < 1)
            return SHAREMIND_MODULE_API_0x1_INVALID_CALL;

        const std::string key(static_cast<char const * const>(crefs[0].pData), crefs[0].size - 1);

        mod.logger.debug() << "keydb_get_size with key \"" << key << '\"';

        auto reply(getClient(c).command("GET %s", key.c_str()));
        const std::string & data = reply.asString();

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
            << refs[0].size << ", " << data->size();

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

        getClient(c).command("DEL %b",
                             static_cast<char const * const>(crefs[0].pData),
                             crefs[0].size - 1);
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
